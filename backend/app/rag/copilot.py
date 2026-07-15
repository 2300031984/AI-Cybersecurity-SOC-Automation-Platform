import os
import re
import json
from typing import List, Dict, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime

# LangChain Imports
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferMemory
from langchain_google_genai import ChatGoogleGenerativeAI

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.prompts.templates import SQL_GENERATOR_PROMPT, THREAT_SUMMARY_PROMPT

# Safe read-only SQL patterns
SQL_BLACKLIST = re.compile(
    r"\b(update|delete|insert|drop|truncate|alter|create|grant|revoke|replace|merge|execute|dbcc|exec|union\s+all|union)\b", 
    re.IGNORECASE
)

def validate_sql_safety(sql: str) -> bool:
    """
    Checks if a generated SQL query is safe and is exclusively a SELECT query.
    """
    stripped = sql.strip().lower()
    if not stripped.startswith("select"):
        return False
    if SQL_BLACKLIST.search(stripped):
        return False
    return True

class SecurityCopilotRAG:
    """
    Modular AI Security Copilot utilizing LangChain, conversation memory,
    and PostgreSQL to execute Retrieval-Augmented Generation (RAG).
    """
    def __init__(self):
        self.memory = ConversationBufferMemory(
            memory_key="chat_history", 
            return_messages=False
        )
        self.is_gemini_active = False
        
        if settings.GEMINI_API_KEY:
            try:
                self.llm = ChatGoogleGenerativeAI(
                    model="gemini-2.5-flash",
                    google_api_key=settings.GEMINI_API_KEY,
                    temperature=0.2
                )
                self.is_gemini_active = True
                logger.info("LangChain Gemini LLM initialized for RAG Copilot.")
            except Exception as e:
                logger.error(f"Failed to initialize LangChain Gemini LLM: {str(e)}")
                
    def get_sql_query(self, question: str, organization_id: Optional[int] = None) -> str:
        """
        Translates a natural language question into a PostgreSQL SELECT query.
        """
        if self.is_gemini_active:
            try:
                org_filter_instruction = ""
                if organization_id is not None:
                    org_filter_instruction = f"IMPORTANT: You MUST filter the query by organization_id = {organization_id} when querying vulnerabilities, ai_analysis, workflow_logs, or audit_logs tables."
                
                # Setup prompt
                prompt = PromptTemplate(
                    input_variables=["question", "org_filter_instruction"],
                    template=SQL_GENERATOR_PROMPT
                )
                formatted = prompt.format(question=question, org_filter_instruction=org_filter_instruction)
                
                # Invoke LLM
                response = self.llm.invoke(formatted)
                sql = response.content.strip()
                
                # Strip potential markdown formatting
                sql = re.sub(r"^```sql\s*", "", sql, flags=re.IGNORECASE)
                sql = re.sub(r"\s*```$", "", sql)
                sql = sql.strip().replace(";", "")
                
                if sql and validate_sql_safety(sql):
                    return sql
            except Exception as e:
                logger.warning(f"LangChain SQL generation failed: {str(e)}")
                
        # Rule-based fallback parsing if Gemini is offline or failed
        org_clause = f"organization_id = {organization_id}" if organization_id is not None else "1=1"
        q_lower = question.lower()
        if "critical" in q_lower:
            return f"SELECT cve_id, title, cvss_score, severity FROM vulnerabilities WHERE (cvss_score >= 9.0 OR severity = 'CRITICAL') AND {org_clause} ORDER BY cvss_score DESC LIMIT 10"
        elif "latest" in q_lower or "today" in q_lower:
            return f"SELECT cve_id, title, cvss_score, severity, published_date FROM vulnerabilities WHERE {org_clause} ORDER BY published_date DESC LIMIT 10"
        elif "microsoft" in q_lower:
            return f"SELECT v.cve_id, v.title, v.cvss_score, v.severity FROM vulnerabilities v JOIN vendors vend ON v.vendor_id = vend.id WHERE vend.name ILIKE '%Microsoft%' AND v.{org_clause} LIMIT 10"
        elif "cisa" in q_lower or "kev" in q_lower:
            return f"SELECT v.cve_id, v.title, v.cvss_score, k.date_added FROM vulnerabilities v JOIN cisa_kev k ON v.cve_id = k.cve_id WHERE v.{org_clause} LIMIT 10"
        elif "epss" in q_lower:
            return f"SELECT v.cve_id, v.title, e.score, e.percentile FROM vulnerabilities v JOIN epss e ON v.cve_id = e.cve_id WHERE v.{org_clause} ORDER BY e.score DESC LIMIT 10"
        else:
            return f"SELECT cve_id, title, cvss_score, severity FROM vulnerabilities WHERE {org_clause} LIMIT 10"

    def execute_query(self, db: Session, sql: str, organization_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Executes the query string safely and returns result row dictionaries.
        Enforces organization_id constraint if present to guarantee tenant isolation.
        """
        if not sql or not validate_sql_safety(sql):
            return [{"error": "Generated SQL query was blocked by safety parameters."}]
            
        # Programmatic injection for Row-Level Tenant Security
        if organization_id is not None and "organization_id" not in sql.lower():
            # Check if query is targeting tables that support organization filtering
            if any(table in sql.lower() for table in ["vulnerabilities", "ai_analysis", "workflow_logs", "audit_logs"]):
                # Append constraint intelligently
                if "where" in sql.lower():
                    # Check for ORDER BY, LIMIT, or GROUP BY to insert before them
                    order_idx = sql.lower().find("order by")
                    limit_idx = sql.lower().find("limit")
                    group_idx = sql.lower().find("group by")
                    
                    indices = [i for i in [order_idx, limit_idx, group_idx] if i > -1]
                    if indices:
                        insert_pos = min(indices)
                        sql = sql[:insert_pos] + f" AND organization_id = {organization_id} " + sql[insert_pos:]
                    else:
                        sql += f" AND organization_id = {organization_id}"
                else:
                    order_idx = sql.lower().find("order by")
                    limit_idx = sql.lower().find("limit")
                    group_idx = sql.lower().find("group by")
                    
                    indices = [i for i in [order_idx, limit_idx, group_idx] if i > -1]
                    if indices:
                        insert_pos = min(indices)
                        sql = sql[:insert_pos] + f" WHERE organization_id = {organization_id} " + sql[insert_pos:]
                    else:
                        sql += f" WHERE organization_id = {organization_id}"
                        
        try:
            result = db.execute(text(sql))
            columns = result.keys()
            return [dict(zip(columns, row)) for row in result.fetchall()]
        except Exception as e:
            logger.error(f"SQL Execution Error: {str(e)}")
            return [{"error": f"Database execution error: {str(e)}"}]

    def ask(self, db: Session, question: str, organization_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Main RAG pipeline:
        1. Translates NL -> SQL SELECT (incorporating tenant filters).
        2. Executes SELECT -> database context safely.
        3. Invokes LLM (with conversation history memory) to compile response.
        """
        # Generate SQL
        sql_query = self.get_sql_query(question, organization_id=organization_id)
        
        # Execute query
        context_data = self.execute_query(db, sql_query, organization_id=organization_id)
        
        # Retrieve history from memory
        chat_history = self.memory.load_memory_variables({}).get("chat_history", "")
        
        # Invoke LLM for synthesis
        answer = ""
        if self.is_gemini_active:
            try:
                prompt = PromptTemplate(
                    input_variables=["chat_history", "context_data", "question"],
                    template=THREAT_SUMMARY_PROMPT
                )
                formatted = prompt.format(
                    chat_history=chat_history,
                    context_data=json.dumps(context_data, default=str),
                    question=question
                )
                
                response = self.llm.invoke(formatted)
                answer = response.content.strip()
            except Exception as e:
                logger.warning(f"LangChain synthesis failed, compiling mock response: {str(e)}")
                
        # Mock compilation if Gemini is offline
        if not answer:
            cves = [r.get("cve_id") for r in context_data if "cve_id" in r]
            cves_str = ", ".join(cves) if cves else "no active matches"
            
            answer = f"According to search results, the matching vulnerability records are: {cves_str}. "
            if len(context_data) > 0 and "cve_id" in context_data[0]:
                answer += "\n\nKey Vulnerability Highlights:\n"
                for r in context_data[:5]:
                    answer += f"- **{r.get('cve_id')}**: {r.get('title', 'No Title')} (Score: {r.get('cvss_score', r.get('score', 'N/A'))})\n"
            else:
                answer += "Please check system dashboards for active alert tables."
                
        # Save memory state
        self.memory.save_context({"input": question}, {"output": answer})
        
        return {
            "answer": answer,
            "source_query": sql_query,
            "source_data": context_data
        }

# Global singleton orchestrator
copilot_rag = SecurityCopilotRAG()
