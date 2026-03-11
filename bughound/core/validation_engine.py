"""
BugHound Validation Engine

This module provides deterministic validation logic for security findings.
It aims to reduce false positives by applying strict, rule-based checks
on evidential data (headers, response bodies, etc.) without executing
active scanners or utilizing AI models.
"""

from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any, Optional
import json
import re

@dataclass
class ValidationResult:
    """
    Represents the outcome of a validation attempt.
    
    Attributes:
        status: The validation verdict ("confirmed", "likely", "false_positive").
        confidence: Integer score (0-100) indicating certainty.
        reason: Human-readable explanation of the decision.
        evidence_refs: List of keys or references to the evidence used.
    """
    status: str
    confidence: int  # 0-100
    reason: str
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class ValidationEngine:
    """
    Deterministically validates scanner findings based on rigid rules.
    """

    # Common SQL Error Signatures (Simple V1 List)
    SQL_ERRORS = [
        "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL query",
        "SQLite/JDBCDriver", "System.Data.SqlClient", "syntax error"
    ]

    def validate_finding(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> ValidationResult:
        """
        Validate a finding using provided evidence.
        
        Args:
            finding: Dictionary describing the issue (must contain 'type').
            evidence: Dictionary containing 'headers', 'body', 'payload', etc.
        
        Returns:
            ValidationResult object.
        """
        vuln_type = finding.get("type", "").lower()
        
        if "cors" in vuln_type:
            return self._validate_cors(evidence)
        elif "xss" in vuln_type or "script" in vuln_type:
            return self._validate_xss(finding, evidence)
        elif "idor" in vuln_type:
            return self._validate_idor(evidence)
        elif "sql" in vuln_type or "injection" in vuln_type:
            return self._validate_sqli(evidence)
        
        # Default fallback for unknown types
        return ValidationResult(
            status="likely",
            confidence=10,
            reason="No specific validation rule for this finding type.",
            evidence_refs=[]
        )

    def _validate_cors(self, evidence: Dict[str, Any]) -> ValidationResult:
        """
        Validate CORS Misconfiguration.
        Rule: Access-Control-Allow-Credentials=true AND (Origin Reflected OR Wildcard)
        """
        headers = evidence.get("response_headers", {})
        # Normalize headers to lowercase keys
        headers = {k.lower(): v for k, v in headers.items()}
        
        acac = headers.get("access-control-allow-credentials", "").lower()
        acao = headers.get("access-control-allow-origin", "")
        
        if acac == "true":
            if acao == "*" or (evidence.get("origin") and acao == evidence.get("origin")):
                return ValidationResult(
                    status="confirmed",
                    confidence=95,
                    reason="Critical CORS: Credentials allowed with wildcard or reflected origin.",
                    evidence_refs=["Access-Control-Allow-Credentials", "Access-Control-Allow-Origin"]
                )
            return ValidationResult(
                status="likely",
                confidence=60,
                reason="Credentials allowed but origin validation unclear.",
                evidence_refs=["Access-Control-Allow-Credentials"]
            )
            
        return ValidationResult(
            status="false_positive",
            confidence=90,
            reason="Access-Control-Allow-Credentials not set to true.",
            evidence_refs=[]
        )

    def _validate_xss(self, finding: Dict[str, Any], evidence: Dict[str, Any]) -> ValidationResult:
        """
        Validate Reflected XSS.
        Rule: Payload must appear raw (unescaped) in the body.
        """
        payload = finding.get("payload", "")
        body = evidence.get("response_body", "")
        
        if not payload or not body:
            return ValidationResult(
                status="likely",
                confidence=20,
                reason="Missing payload or response body for analysis.",
                evidence_refs=[]
            )

        if payload in body:
            # Simple check: is it inside a safe context? (Not handling complex context analysis in V1)
            return ValidationResult(
                status="likely",
                confidence=80,
                reason=f"Payload '{payload}' found verbatim in response.",
                evidence_refs=["response_body"]
            )
            
        # Check for HTML escaped version
        import html
        escaped_payload = html.escape(payload)
        if escaped_payload in body:
             return ValidationResult(
                status="false_positive",
                confidence=95,
                reason=f"Payload found but HTML escaped: '{escaped_payload}'",
                evidence_refs=["response_body"]
            )

        return ValidationResult(
            status="false_positive", 
            confidence=70, 
            reason="Payload not found in response body.",
            evidence_refs=[]
        )

    def _validate_sqli(self, evidence: Dict[str, Any]) -> ValidationResult:
        """
        Validate SQL Injection (Error-Based).
        Rule: Known SQL error message present in body.
        """
        body = evidence.get("response_body", "").lower()
        
        for error in self.SQL_ERRORS:
            if error.lower() in body:
                return ValidationResult(
                    status="likely", # Error-based is usually likely, confirmed if manual check passes
                    confidence=85,
                    reason=f"Database error signature detected: '{error}'",
                    evidence_refs=["response_body"]
                )
                
        return ValidationResult(
            status="false_positive",
            confidence=50,
            reason="No database error signatures found.",
            evidence_refs=[]
        )

    def _validate_idor(self, evidence: Dict[str, Any]) -> ValidationResult:
        """
        Validate IDOR.
        Rule: Response data diff between object IDs.
        Evidence must contain 'response_1' (authorized) and 'response_2' (unauthorized accessing object 1).
        This is tricky for a static validator, assuming 'diff_found' boolean provided by scanner wrapper.
        """
        diff_found = evidence.get("diff_found", False)
        status_1 = evidence.get("status_1")
        status_2 = evidence.get("status_2")
        
        if diff_found and status_1 == 200 and status_2 == 200:
             return ValidationResult(
                status="confirmed",
                confidence=90,
                reason="Object data returned for unauthorized request.",
                evidence_refs=["response_diff"]
            )
            
        return ValidationResult(
            status="likely",
            confidence=30,
            reason="IDOR check inconclusive without clear data diff.",
            evidence_refs=[]
        )

# --- Test Block ---
if __name__ == "__main__":
    engine = ValidationEngine()
    
    print("--- Validation Engine Test ---\n")

    # 1. Confirmed CORS
    print("Test 1: Confirmed CORS")
    finding_cors = {"type": "CORS Misconfiguration"}
    evidence_cors = {
        "origin": "http://evil.com",
        "response_headers": {
            "Access-Control-Allow-Origin": "http://evil.com",
            "Access-Control-Allow-Credentials": "true"
        }
    }
    result_cors = engine.validate_finding(finding_cors, evidence_cors)
    print(json.dumps(result_cors.to_dict(), indent=2))
    
    # 2. False Positive XSS (Escaped)
    print("\nTest 2: False Positive XSS")
    finding_xss = {"type": "Reflected XSS", "payload": "<script>alert(1)</script>"}
    evidence_xss = {
        "response_body": "<html><body>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
    }
    result_xss = engine.validate_finding(finding_xss, evidence_xss)
    print(json.dumps(result_xss.to_dict(), indent=2))

    # 3. Likely SQLi
    print("\nTest 3: Likely SQLi")
    finding_sqli = {"type": "SQL Injection"}
    evidence_sqli = {
        "response_body": "Internal Server Error: Syntax error in SQL statement near '1''"
    }
    result_sqli = engine.validate_finding(finding_sqli, evidence_sqli)
    print(json.dumps(result_sqli.to_dict(), indent=2))
