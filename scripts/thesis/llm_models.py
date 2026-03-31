#!/usr/bin/env python3
"""
Pydantic models for LLM-based vulnerability analysis.

These models define the structured output format for GPT analysis
of Java code for security vulnerabilities.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class VulnerabilityCategory(str, Enum):
    """Vulnerability categories aligned with OWASP Benchmark and CWE."""
    
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    PATHTRAVER = "pathtraver"
    CRYPTO = "crypto"
    HASH = "hash"
    WEAKRAND = "weakrand"
    TRUSTBOUND = "trustbound"
    SECURECOOKIE = "securecookie"
    LDAPI = "ldapi"
    XPATHI = "xpathi"
    NONE = "none"


class FileAnalysis(BaseModel):
    """Analysis result for a single Java file."""
    
    test_name: str = Field(
        ...,
        description="Test name extracted from filename, e.g., BenchmarkTest00018"
    )
    is_vulnerable: bool = Field(
        ...,
        description="Whether the code contains a real exploitable vulnerability (not a false positive)"
    )
    category: Optional[VulnerabilityCategory] = Field(
        None,
        description="Vulnerability category if detected, None if not vulnerable"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0"
    )
    reasoning: str = Field(
        ...,
        description="Brief explanation of the decision (1-2 sentences)"
    )


class BatchAnalysis(BaseModel):
    """Batch analysis result for multiple Java files."""
    
    analyses: List[FileAnalysis] = Field(
        ...,
        description="List of analysis results for each file in the batch"
    )


CWE_DESCRIPTIONS = {
    VulnerabilityCategory.SQLI: "CWE-89: SQL Injection - unvalidated user data in SQL queries",
    VulnerabilityCategory.XSS: "CWE-79: Cross-Site Scripting - unvalidated data in HTML response",
    VulnerabilityCategory.CMDI: "CWE-78: Command Injection - unvalidated data in OS commands",
    VulnerabilityCategory.PATHTRAVER: "CWE-22: Path Traversal - unvalidated file paths",
    VulnerabilityCategory.CRYPTO: "CWE-327: Weak Cryptography - weak encryption algorithms (DES, RC4, etc.)",
    VulnerabilityCategory.HASH: "CWE-328: Weak Hash - weak hashing functions (MD5, SHA1 for passwords)",
    VulnerabilityCategory.WEAKRAND: "CWE-330: Weak Randomness - using java.util.Random instead of SecureRandom",
    VulnerabilityCategory.TRUSTBOUND: "CWE-501: Trust Boundary Violation - user data in session without validation",
    VulnerabilityCategory.SECURECOOKIE: "CWE-614: Insecure Cookie - missing Secure flag on cookies",
    VulnerabilityCategory.LDAPI: "CWE-90: LDAP Injection - unvalidated data in LDAP queries",
    VulnerabilityCategory.XPATHI: "CWE-643: XPath Injection - unvalidated data in XPath queries",
}
