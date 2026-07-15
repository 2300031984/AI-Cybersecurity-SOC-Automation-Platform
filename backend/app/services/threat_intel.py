import requests
import gzip
import csv
import io
import time
from datetime import datetime, date, timedelta, timezone
from sqlalchemy.orm import Session
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.vendor import Vendor
from backend.app.models.product import Product
from backend.app.models.cisa_kev import CisaKev
from backend.app.models.epss import Epss
from backend.app.models.workflow_logs import WorkflowLog
from backend.app.core.logging import logger
from backend.app.core.config import settings

def log_workflow_execution(db: Session, source: str, action: str, status: str, details: str):
    """
    Utility helper to log automation workflow executions to the database.
    """
    try:
        log_entry = WorkflowLog(
            source=source,
            action_type=action,
            status=status,
            details=details
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log workflow execution: {str(e)}")

def get_or_create_vendor_and_product(db: Session, vendor_name: str, product_name: str):
    """
    Resolves vendor and product names to database IDs. Creates them if they do not exist.
    Guards against long names and unique constraint conflicts.
    """
    if not vendor_name:
        vendor_name = "Unknown"
    if not product_name:
        product_name = "Unknown"
        
    vendor_name = vendor_name.strip()
    product_name = product_name.strip()
    
    # Enforce safe upper bounds
    if len(vendor_name) > 500:
        logger.warning(f"Unusually long vendor name truncated during NVD lookup: {vendor_name[:100]}... length={len(vendor_name)}")
        vendor_name = vendor_name[:500]
    if len(product_name) > 500:
        logger.warning(f"Unusually long product name truncated during NVD lookup: {product_name[:100]}... length={len(product_name)}")
        product_name = product_name[:500]
        
    # Resolve Vendor (Case-Insensitive check)
    vendor = db.query(Vendor).filter(Vendor.name.ilike(vendor_name)).first()
    if not vendor:
        try:
            sp = db.begin_nested()
            vendor = Vendor(name=vendor_name)
            db.add(vendor)
            db.flush()
            sp.commit()
        except Exception:
            db.rollback()
            # If unique constraint conflict, fetch existing
            vendor = db.query(Vendor).filter(Vendor.name.ilike(vendor_name)).first()
            if not vendor:
                raise
        
    # Resolve Product (Case-Insensitive check)
    product = db.query(Product).filter(
        Product.vendor_id == vendor.id,
        Product.name.ilike(product_name)
    ).first()
    if not product:
        try:
            sp = db.begin_nested()
            product = Product(vendor_id=vendor.id, name=product_name)
            db.add(product)
            db.flush()
            sp.commit()
        except Exception:
            db.rollback()
            # If unique constraint conflict, fetch existing
            product = db.query(Product).filter(
                Product.vendor_id == vendor.id,
                Product.name.ilike(product_name)
            ).first()
            if not product:
                raise
        
    return vendor.id, product.id

def fetch_cisa_feed_with_retry(url: str, retries: int = 3, backoff: float = 2.0) -> dict:
    """
    Fetches the CISA KEV JSON dataset with retry logic and exponential backoff.
    """
    for attempt in range(1, retries + 1):
        try:
            logger.info(f"Fetching CISA KEV feed (attempt {attempt}/{retries})...")
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"CISA KEV connection failed on attempt {attempt}: {str(e)}")
            if attempt == retries:
                raise e
            time.sleep(backoff * attempt)

def sync_cisa_kev(db: Session) -> dict:
    """
    Fetches CISA KEV JSON, caches active DB records, parses elements with sub-transactions,
    handles long values cleanly, and returns a detailed execution summary.
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    logger.info("Starting production-grade CISA KEV database synchronization...")
    start_time = time.time()
    
    summary = {
        "vendors_created": 0,
        "products_created": 0,
        "cves_created": 0,
        "records_updated": 0,
        "records_skipped": 0,
        "execution_time_seconds": 0.0,
        "errors": []
    }
    
    try:
        # Fetch data with built-in retry
        data = fetch_cisa_feed_with_retry(url)
        cisa_vulns = data.get("vulnerabilities", [])
        
        # Cache existing tables to prevent duplicate queries and optimize speed
        existing_vendors = db.query(Vendor.id, Vendor.name).all()
        vendor_cache = {v.name.lower(): v.id for v in existing_vendors}
        
        existing_products = db.query(Product.id, Product.vendor_id, Product.name).all()
        product_cache = {(p.vendor_id, p.name.lower()): p.id for p in existing_products}
        
        # Caching Vulnerabilities
        logger.info("Caching existing vulnerability IDs...")
        existing_vulns = {v.cve_id: v for v in db.query(Vulnerability).all()}
        
        # Caching CisaKev links
        logger.info("Caching existing CISA catalog mappings...")
        existing_cisa = {c.cve_id: c for c in db.query(CisaKev).all()}
        
        for v in cisa_vulns:
            cve_id = v.get("cveID")
            if not cve_id:
                summary["records_skipped"] += 1
                continue
                
            # DB Savepoint Sub-transaction (continues on individual failures)
            sp = db.begin_nested()
            try:
                vendor_name = v.get("vendorProject", "Unknown")
                product_name = v.get("product", "Unknown")
                
                if not vendor_name:
                    vendor_name = "Unknown"
                vendor_name = vendor_name.strip()
                if len(vendor_name) > 500:
                    logger.warning(f"Unusually long vendor name detected: {vendor_name[:100]}... length={len(vendor_name)}")
                    vendor_name = vendor_name[:500]
                    
                if not product_name:
                    product_name = "Unknown"
                product_name = product_name.strip()
                if len(product_name) > 400:
                    logger.warning(f"Unusually long product name detected: {product_name[:100]}... length={len(product_name)}")
                    if len(product_name) > 500:
                        product_name = product_name[:500]
                
                # Resolve Vendor ID from memory cache or DB
                v_key = vendor_name.lower()
                vendor_id = vendor_cache.get(v_key)
                if not vendor_id:
                    vendor_obj = Vendor(name=vendor_name)
                    db.add(vendor_obj)
                    db.flush()
                    vendor_id = vendor_obj.id
                    vendor_cache[v_key] = vendor_id
                    summary["vendors_created"] += 1
                    
                # Resolve Product ID from memory cache or DB
                p_key = (vendor_id, product_name.lower())
                product_id = product_cache.get(p_key)
                if not product_id:
                    product_obj = Product(vendor_id=vendor_id, name=product_name)
                    db.add(product_obj)
                    db.flush()
                    product_id = product_obj.id
                    product_cache[p_key] = product_id
                    summary["products_created"] += 1
                    
                # Resolve Vulnerability Title size
                title = v.get("vulnerabilityName", f"CISA KEV CVE placeholder {cve_id}")
                if len(title) > 500:
                    logger.warning(f"Unusually long vulnerability title detected: {title[:100]}... length={len(title)}")
                    title = title[:500]
                    
                description = v.get("shortDescription", "No description available yet. Synchronized via CISA KEV.")
                
                # Retrieve or create Vulnerability
                vuln = existing_vulns.get(cve_id)
                is_new_vuln = False
                if not vuln:
                    vuln = Vulnerability(
                        cve_id=cve_id,
                        title=title,
                        description=description,
                        severity="CRITICAL",
                        cvss_score=8.5,
                        vendor_id=vendor_id,
                        product_id=product_id,
                        published_date=datetime.now(timezone.utc)
                    )
                    db.add(vuln)
                    db.flush()
                    existing_vulns[cve_id] = vuln
                    summary["cves_created"] += 1
                    is_new_vuln = True
                    
                # Parse dates
                date_added_str = v.get("dateAdded")
                due_date_str = v.get("dueDate")
                
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date() if date_added_str else date.today()
                due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None
                
                action_required = v.get("requiredAction", "Apply patches immediately.")
                short_description = v.get("shortDescription", "")
                
                # Update KEV catalog
                cisa_entry = existing_cisa.get(cve_id)
                if not cisa_entry:
                    cisa_entry = CisaKev(
                        cve_id=cve_id,
                        date_added=date_added,
                        due_date=due_date,
                        action_required=action_required,
                        short_description=short_description
                    )
                    db.add(cisa_entry)
                    summary["records_updated"] += 1
                else:
                    cisa_entry.date_added = date_added
                    cisa_entry.due_date = due_date
                    cisa_entry.action_required = action_required
                    cisa_entry.short_description = short_description
                    if not is_new_vuln:
                        summary["records_updated"] += 1
                
                # Commit nested transaction
                sp.commit()
                
            except Exception as row_err:
                sp.rollback()
                summary["records_skipped"] += 1
                err_detail = f"CVE {cve_id} skipped: {str(row_err)}"
                logger.error(err_detail)
                summary["errors"].append(err_detail)
                
        # Commit top-level transaction
        db.commit()
        
        execution_time = round(time.time() - start_time, 2)
        summary["execution_time_seconds"] = execution_time
        
        details = (
            f"CISA KEV Sync Complete. Ingested {len(cisa_vulns)} items. "
            f"Created: Vendors={summary['vendors_created']}, Products={summary['products_created']}, CVEs={summary['cves_created']}. "
            f"Updated: {summary['records_updated']}, Skipped: {summary['records_skipped']}. Time={execution_time}s."
        )
        logger.info(details)
        log_workflow_execution(db, "CISA KEV Sync", "Sync Catalog", "SUCCESS", details)
        
        return {
            "status": "SUCCESS", 
            "details": details,
            "summary": summary
        }
        
    except Exception as e:
        db.rollback()
        execution_time = round(time.time() - start_time, 2)
        summary["execution_time_seconds"] = execution_time
        err_msg = f"CISA KEV sync failed: {str(e)}"
        logger.error(err_msg)
        log_workflow_execution(db, "CISA KEV Sync", "Sync Catalog", "FAILED", err_msg)
        return {
            "status": "FAILED", 
            "details": err_msg,
            "summary": summary
        }

def sync_epss(db: Session) -> dict:
    """
    Downloads First.org's daily EPSS CSV gzip dataset, parses values,
    and updates EPSS scores *only* for the CVEs that already exist in our DB
    for maximum database efficiency.
    """
    url = "https://epss.first.org/epss-data-latest.csv.gz"
    logger.info("Starting EPSS database synchronization...")
    
    try:
        # Check active CVE count
        known_cves = {cve[0] for cve in db.query(Vulnerability.cve_id).all()}
        if not known_cves:
            details = "Skipped EPSS sync: No vulnerabilities exist in database to match scores against."
            logger.info(details)
            return {"status": "SUCCESS", "details": details}
            
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Decompress gzip in memory
        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as f:
            csv_content = f.read().decode("utf-8")
            
        # Parse CSV (skip metadata header line starting with #)
        csv_lines = csv_content.splitlines()
        data_start_idx = 0
        for idx, line in enumerate(csv_lines):
            if line.startswith("cve,epss,percentile"):
                data_start_idx = idx
                break
                
        reader = csv.DictReader(csv_lines[data_start_idx:])
        updated_count = 0
        
        for row in reader:
            cve_id = row.get("cve")
            if cve_id in known_cves:
                score = float(row.get("epss", 0.0))
                percentile = float(row.get("percentile", 0.0))
                
                epss_record = db.query(Epss).filter(Epss.cve_id == cve_id).first()
                if not epss_record:
                    epss_record = Epss(
                        cve_id=cve_id,
                        score=score,
                        percentile=percentile,
                        retrieved_at=datetime.now(timezone.utc)
                    )
                    db.add(epss_record)
                else:
                    epss_record.score = score
                    epss_record.percentile = percentile
                    epss_record.retrieved_at = datetime.now(timezone.utc)
                    
                updated_count += 1
                
        db.commit()
        details = f"EPSS sync complete. Updated {updated_count} CVE risk profiles."
        logger.info(details)
        log_workflow_execution(db, "EPSS Sync", "Update EPSS scores", "SUCCESS", details)
        return {"status": "SUCCESS", "details": details}
        
    except Exception as e:
        db.rollback()
        err_msg = f"EPSS sync failed: {str(e)}"
        logger.error(err_msg)
        log_workflow_execution(db, "EPSS Sync", "Update EPSS scores", "FAILED", err_msg)
        return {"status": "FAILED", "details": err_msg}

def enrich_cve_from_nvd(db: Session, cve_id: str) -> bool:
    """
    Queries the official NVD API to fetch metadata for a specific CVE
    and updates/inserts it into the database.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY
        
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code != 200:
            logger.warning(f"CVE enrichment failed for {cve_id}: NVD responded with status code {response.status_code}")
            return False
            
        data = response.json()
        v_list = data.get("vulnerabilities", [])
        if not v_list:
            logger.warning(f"No NVD vulnerability details found for {cve_id}")
            return False
            
        nvd_cve = v_list[0].get("cve", {})
        
        # Descriptions
        desc_list = nvd_cve.get("descriptions", [])
        description = "No description available."
        for d in desc_list:
            if d.get("lang") == "en":
                description = d.get("value")
                break
                
        # Metrics & CVSS
        metrics = nvd_cve.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = "N/A"
        severity = "INFO"
        
        # Prefer CVSS v3.1, then v3.0, then v2.0
        cvss_data = None
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            
        if cvss_data:
            cvss_score = float(cvss_data.get("baseScore", 0.0))
            cvss_vector = cvss_data.get("vectorString", "N/A")
            base_severity = cvss_data.get("baseSeverity", "INFO")
            severity = base_severity.upper() if isinstance(base_severity, str) else "INFO"
        else:
            # Fallback severity based on score
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"
                
        # Guard vector length limit
        if cvss_vector and len(cvss_vector) > 100:
            logger.warning(f"Truncating long CVSS vector for NVD lookup: {cvss_vector[:50]}...")
            cvss_vector = cvss_vector[:100]

        # Published dates
        pub_date_str = nvd_cve.get("published")
        mod_date_str = nvd_cve.get("lastModified")
        
        published_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00")) if pub_date_str else datetime.now(timezone.utc)
        last_modified = datetime.fromisoformat(mod_date_str.replace("Z", "+00:00")) if mod_date_str else datetime.now(timezone.utc)
        
        # Vendor/product parsing from configurations (CPE)
        vendor_name = "Unknown"
        product_name = "Unknown"
        
        configurations = nvd_cve.get("configurations", [])
        for conf in configurations:
            nodes = conf.get("nodes", [])
            for node in nodes:
                cpe_match = node.get("cpeMatch", [])
                for match in cpe_match:
                    cpe_uri = match.get("criteria", "")
                    if cpe_uri.startswith("cpe:2.3:a:") or cpe_uri.startswith("cpe:2.3:o:"):
                        # Parse CPE URI components
                        parts = cpe_uri.split(":")
                        if len(parts) >= 6:
                            vendor_name = parts[3].replace("_", " ").title()
                            product_name = parts[4].replace("_", " ").title()
                            break
                if product_name != "Unknown":
                    break
            if product_name != "Unknown":
                break
                
        vendor_id, product_id = get_or_create_vendor_and_product(db, vendor_name, product_name)
        
        # Title length guard
        title = f"{vendor_name} {product_name} Vulnerability"
        if len(title) > 500:
            title = title[:497] + "..."

        # Update or create Vulnerability
        vuln = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
        if not vuln:
            vuln = Vulnerability(
                cve_id=cve_id,
                title=title,
                description=description,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                severity=severity,
                published_date=published_date,
                last_modified_date=last_modified,
                vendor_id=vendor_id,
                product_id=product_id
            )
            db.add(vuln)
        else:
            vuln.title = title
            vuln.description = description
            vuln.cvss_score = cvss_score
            vuln.cvss_vector = cvss_vector
            vuln.severity = severity
            vuln.published_date = published_date
            vuln.last_modified_date = last_modified
            vuln.vendor_id = vendor_id
            vuln.product_id = product_id
            
        db.commit()
        logger.info(f"Successfully enriched {cve_id} metadata from NVD API.")
        return True
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to enrich CVE {cve_id} from NVD: {str(e)}")
        return False
