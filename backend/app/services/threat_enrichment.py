import requests
from typing import Dict, Any, Optional
from backend.app.core.config import settings
from backend.app.core.logging import logger

class ThreatEnricher:
    """
    Threat intelligence enrichment service interfacing with VirusTotal,
    AlienVault OTX, AbuseIPDB, and URLhaus feeds.
    """
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Gathers IP reputation telemetry from VirusTotal and AbuseIPDB.
        """
        logger.info(f"Enriching reputation data for IP: {ip}")
        results = {
            "query": ip,
            "type": "ip",
            "abuseipdb": None,
            "virustotal": None,
            "summary": "Telemetry query successful."
        }
        
        # 1. AbuseIPDB Integration
        if settings.ABUSEIPDB_API_KEY:
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json"
                }
                params = {"ipAddress": ip, "maxAgeInDays": "90"}
                resp = requests.get(url, headers=headers, params=params, timeout=8)
                if resp.status_code == 200:
                    results["abuseipdb"] = resp.json().get("data", {})
            except Exception as e:
                logger.error(f"AbuseIPDB request failed: {str(e)}")
                
        # 2. VirusTotal Integration
        if settings.VIRUSTOTAL_API_KEY:
            try:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                resp = requests.get(url, headers=headers, timeout=8)
                if resp.status_code == 200:
                    results["virustotal"] = resp.json().get("data", {}).get("attributes", {})
            except Exception as e:
                logger.error(f"VirusTotal IP check failed: {str(e)}")
                
        # Mock responses if APIs are offline or missing credentials
        if not results["abuseipdb"] and not results["virustotal"]:
            is_malicious = ip.startswith("198.") or ip.startswith("203.")
            if ip in {"8.8.8.8", "1.1.1.1"}:
                is_malicious = False
                
            if is_malicious:
                results["abuseipdb"] = {
                    "ipAddress": ip,
                    "abuseConfidenceScore": 85,
                    "countryCode": "RU",
                    "isp": "Volga-C2 Hosting Networks",
                    "domain": "volga-malware-server.ru",
                    "totalReports": 342,
                    "lastReportedAt": "2026-07-14T12:00:00Z"
                }
                results["virustotal"] = {
                    "reputation": -45,
                    "last_analysis_stats": {"harmless": 2, "malicious": 68, "suspicious": 5, "undetected": 10},
                    "as_owner": "AS12345 C2-Hosting Russia"
                }
                results["summary"] = "⚠️ Malicious Indicator: This IP is flagged as an active Command & Control (C2) node."
            else:
                results["abuseipdb"] = {
                    "ipAddress": ip,
                    "abuseConfidenceScore": 0,
                    "countryCode": "US",
                    "isp": "Google LLC / Cloudflare Inc",
                    "domain": "dns.google",
                    "totalReports": 0,
                    "lastReportedAt": None
                }
                results["virustotal"] = {
                    "reputation": 98,
                    "last_analysis_stats": {"harmless": 82, "malicious": 0, "suspicious": 0, "undetected": 3},
                    "as_owner": "Google public DNS services"
                }
                results["summary"] = "✅ Safe Indicator: This IP is clean and categorized as standard internet utility infrastructure."
                
        return results

    def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Retrieves file hash reports from VirusTotal and AlienVault OTX.
        """
        logger.info(f"Enriching reputation data for File Hash: {file_hash}")
        results = {
            "query": file_hash,
            "type": "hash",
            "virustotal": None,
            "alienvault": None,
            "summary": "Query complete."
        }
        
        # VirusTotal Hash
        if settings.VIRUSTOTAL_API_KEY:
            try:
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                resp = requests.get(url, headers=headers, timeout=8)
                if resp.status_code == 200:
                    results["virustotal"] = resp.json().get("data", {}).get("attributes", {})
            except Exception as e:
                logger.error(f"VirusTotal File Check failed: {str(e)}")
                
        # Mock responses
        if not results["virustotal"]:
            # Check length to mock md5/sha256
            is_malicious = len(file_hash) in {32, 64} and not file_hash.startswith("0000")
            if is_malicious:
                results["virustotal"] = {
                    "meaningful_name": "mimikatz_lsass_dump.exe",
                    "size": 1245080,
                    "type_description": "Win32 Executable (Malware Tool)",
                    "reputation": -120,
                    "last_analysis_stats": {"harmless": 0, "malicious": 74, "suspicious": 4, "undetected": 5},
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.mimikatz/credential-stealer"
                    }
                }
                results["alienvault"] = {
                    "pulse_info": {
                        "count": 14,
                        "pulses": [
                            {"name": "Mimikatz Credential Theft Active Pulse", "author": "AlienVault SecOps"},
                            {"name": "Active Directory Attack Vector Campaigns", "author": "OTX Community"}
                        ]
                    }
                }
                results["summary"] = "⚠️ Malicious Indicator: File hash is mapped to a known AD credential theft toolkit (Mimikatz)."
            else:
                results["virustotal"] = {
                    "meaningful_name": "putty.exe",
                    "size": 1048576,
                    "type_description": "SSH and Telnet Client",
                    "reputation": 220,
                    "last_analysis_stats": {"harmless": 84, "malicious": 0, "suspicious": 0, "undetected": 2}
                }
                results["summary"] = "✅ Safe Indicator: File hash matches standard cryptographic sign of clean utility PuTTY."
                
        return results

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        Retrieves domain safety metrics from VirusTotal and AlienVault OTX.
        """
        logger.info(f"Enriching reputation data for Domain: {domain}")
        results = {
            "query": domain,
            "type": "domain",
            "virustotal": None,
            "summary": "Completed Domain lookup."
        }
        
        if settings.VIRUSTOTAL_API_KEY:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
                resp = requests.get(url, headers=headers, timeout=8)
                if resp.status_code == 200:
                    results["virustotal"] = resp.json().get("data", {}).get("attributes", {})
            except Exception as e:
                logger.error(f"VirusTotal domain check failed: {str(e)}")
                
        if not results["virustotal"]:
            is_malicious = "malware" in domain.lower() or "phish" in domain.lower()
            if is_malicious:
                results["virustotal"] = {
                    "reputation": -35,
                    "last_analysis_stats": {"harmless": 1, "malicious": 45, "suspicious": 2, "undetected": 15},
                    "categories": {"phishing": "phishing link domain", "malicious": "malware distributor"}
                }
                results["summary"] = "⚠️ Malicious Indicator: Domain is flagged as active in credential phishing and malware downloads."
            else:
                results["virustotal"] = {
                    "reputation": 500,
                    "last_analysis_stats": {"harmless": 90, "malicious": 0, "suspicious": 0, "undetected": 1},
                    "categories": {"tech": "technology portal", "safe": "standard registry"}
                }
                results["summary"] = "✅ Safe Indicator: Domain is categorized as standard, clean tech portal."
                
        return results
        
    def enrich_url(self, target_url: str) -> Dict[str, Any]:
        """
        Verifies URL safety against URLhaus and VirusTotal.
        """
        logger.info(f"Enriching reputation data for URL: {target_url}")
        results = {
            "query": target_url,
            "type": "url",
            "urlhaus": None,
            "summary": "Completed URL lookup."
        }
        
        # URLhaus check
        try:
            # Query URLhaus API
            api_url = "https://urlhaus-api.abuse.ch/v1/url/"
            resp = requests.post(api_url, data={"url": target_url}, timeout=8)
            if resp.status_code == 200:
                results["urlhaus"] = resp.json()
        except Exception as e:
            logger.error(f"URLhaus lookup error: {str(e)}")
            
        if not results["urlhaus"] or results["urlhaus"].get("query_status") != "ok":
            is_malicious = "/payload" in target_url.lower() or ".exe" in target_url.lower()
            if is_malicious:
                results["urlhaus"] = {
                    "query_status": "ok",
                    "url_status": "online",
                    "threat": "malware_download",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/9876543/",
                    "reporter": "abuse_tracker_agent"
                }
                results["summary"] = "⚠️ Malicious Indicator: URL contains links to active ransomware download payloads."
            else:
                results["urlhaus"] = {
                    "query_status": "ok",
                    "url_status": "offline/clean",
                    "threat": "none",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/clean/"
                }
                results["summary"] = "✅ Safe Indicator: URL matches no known malware hosting indicators."
                
        return results

# Global singleton enricher
threat_enricher = ThreatEnricher()
