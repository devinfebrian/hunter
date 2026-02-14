"""Core data models for Hunter"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnType(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    IDOR = "idor"
    INFO = "info"


class FindingStatus(str, Enum):
    HYPOTHESIZED = "hypothesized"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    SKIPPED = "skipped"


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScopeRule(BaseModel):
    pattern: str
    include: bool = True  # True = in-scope, False = out-of-scope


class Target(BaseModel):
    domain: str
    scope_rules: List[ScopeRule] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    program_type: Optional[str] = None  # HackerOne, Bugcrowd, etc.


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    parameters: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    technology: Optional[str] = None


class Finding(BaseModel):
    model_config = {"use_enum_values": True}
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    vulnerability_type: VulnType
    severity: Severity
    status: FindingStatus = FindingStatus.HYPOTHESIZED
    
    # Location
    url: str
    parameter: Optional[str] = None
    method: str = "GET"
    
    # Evidence
    payload: str
    evidence: str  # Response snippet or error message
    proof_of_concept: Optional[str] = None  # curl command
    
    # Metadata
    title: str
    description: str
    impact: str
    remediation: str
    discovered_by: str = "sqli_agent"
    created_at: datetime = Field(default_factory=lambda: datetime.now())
    
    # Validation
    confirmed: bool = False
    confirmed_at: Optional[datetime] = None


class ExploitRequest(BaseModel):
    target_finding: Finding
    risk_level: RiskLevel
    proposed_action: str
    potential_impact: str
    requires_approval: bool = True


class ScanSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    target: Target
    start_time: datetime = Field(default_factory=lambda: datetime.now())
    end_time: Optional[datetime] = None
    findings: List[Finding] = Field(default_factory=list)
    status: str = "running"  # running, paused, completed, error
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
    
    def get_confirmed_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.confirmed]
