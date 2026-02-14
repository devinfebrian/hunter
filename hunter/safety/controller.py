"""Safety Controller for Hunter - manages risk assessment and approval gates"""

import logging
from enum import Enum
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from hunter.models import Finding, ExploitRequest, RiskLevel, VulnType
from hunter.config import settings

logger = logging.getLogger(__name__)
console = Console()


class SafetyController:
    """Controls safety gates for all Hunter operations"""
    
    # Risk classification for different operations
    RISK_MAP = {
        # SQLi operations
        "sqli_read": RiskLevel.LOW,          # SELECT statements, error-based detection
        "sqli_write": RiskLevel.HIGH,        # INSERT/UPDATE/DELETE
        "sqli_time": RiskLevel.MEDIUM,       # Time-based blind
        "sqli_union": RiskLevel.MEDIUM,      # UNION-based extraction
        
        # Other operations
        "info": RiskLevel.INFO,
        "read": RiskLevel.LOW,
        "write": RiskLevel.HIGH,
        "delete": RiskLevel.CRITICAL,
    }
    
    # Auto-approved operations (safe by default)
    AUTO_APPROVE = {"info", "read", "sqli_read"}
    
    # Blocked operations (never allowed)
    BLOCKED = {"delete", "drop", "truncate", "mass_exfil"}
    
    def __init__(self):
        self.approvals_given = set()
        self.violations = []
    
    def assess_sql_injection(self, finding: Finding) -> ExploitRequest:
        """Assess risk of a SQL injection finding"""
        payload_lower = finding.payload.lower()
        
        # Determine operation type
        if any(kw in payload_lower for kw in ["insert", "update", "delete", "drop"]):
            op_type = "sqli_write"
        elif any(kw in payload_lower for kw in ["sleep", "benchmark", "waitfor", "delay"]):
            op_type = "sqli_time"
        elif "union" in payload_lower:
            op_type = "sqli_union"
        else:
            op_type = "sqli_read"  # Default: error-based or boolean-based detection only
        
        risk_level = self.RISK_MAP.get(op_type, RiskLevel.MEDIUM)
        
        # Check if blocked
        if op_type in self.BLOCKED:
            return ExploitRequest(
                target_finding=finding,
                risk_level=RiskLevel.CRITICAL,
                proposed_action=f"BLOCKED: {op_type}",
                potential_impact="Destructive operation blocked by safety policy",
                requires_approval=False  # Cannot be approved
            )
        
        # Check auto-approve
        auto_approve = (
            settings.safe_mode is False or 
            op_type in self.AUTO_APPROVE or
            risk_level.value in ["info", "low"]
        )
        
        return ExploitRequest(
            target_finding=finding,
            risk_level=risk_level,
            proposed_action=f"Execute {op_type} test on {finding.url}",
            potential_impact=self._get_impact_description(risk_level, finding),
            requires_approval=not auto_approve
        )
    
    def _get_impact_description(self, risk: RiskLevel, finding: Finding) -> str:
        """Get human-readable impact description"""
        descriptions = {
            RiskLevel.INFO: "Information disclosure only",
            RiskLevel.LOW: "Read access to limited data",
            RiskLevel.MEDIUM: "Potential data extraction possible",
            RiskLevel.HIGH: "Data modification possible",
            RiskLevel.CRITICAL: "Data destruction or full database compromise"
        }
        return descriptions.get(risk, "Unknown impact")
    
    def request_approval(self, request: ExploitRequest) -> bool:
        """Request user approval for high-risk operation"""
        if not request.requires_approval:
            return True
        
        if request.risk_level.value in self.BLOCKED:
            console.print(Panel(
                f"[red]BLOCKED: {request.proposed_action}[/red]\n"
                f"This operation is blocked by safety policy.",
                title="Safety Controller",
                border_style="red"
            ))
            return False
        
        # Show approval prompt
        console.print(Panel(
            f"[yellow]Risk Level: {request.risk_level.value.upper()}[/yellow]\n"
            f"Action: {request.proposed_action}\n"
            f"Potential Impact: {request.potential_impact}\n"
            f"Payload: {request.target_finding.payload[:100]}...",
            title="Approval Required",
            border_style="yellow"
        ))
        
        approved = Confirm.ask("Do you want to proceed?")
        
        if approved:
            self.approvals_given.add(request.target_finding.id)
            logger.info(f"Approval given for finding {request.target_finding.id}")
        else:
            logger.info(f"Approval denied for finding {request.target_finding.id}")
        
        return approved
    
    def check_scope(self, url: str, target_domain: str, scope_rules: list) -> bool:
        """Check if URL is within scope"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        
        # Check out-of-scope list first
        for rule in scope_rules:
            if not rule.include:
                pattern = rule.pattern.replace("*.", "").replace("/*", "")
                if pattern in hostname or pattern in url:
                    logger.warning(f"URL {url} matches out-of-scope pattern: {rule.pattern}")
                    self.violations.append({"url": url, "rule": rule.pattern})
                    return False
        
        # Check in-scope
        if not scope_rules:
            # Default: allow target domain and subdomains
            return hostname == target_domain or hostname.endswith(f".{target_domain}")
        
        for rule in scope_rules:
            if rule.include:
                pattern = rule.pattern.replace("*.", "").replace("/*", "")
                if pattern in hostname or pattern in url:
                    return True
        
        # No matching in-scope rule
        if settings.strict_scope:
            logger.warning(f"URL {url} not in scope")
            return False
        
        return True
    
    def validate_rate_limit(self, request_count: int) -> bool:
        """Check if we're within rate limits"""
        max_req = settings.max_requests_per_minute
        if request_count > max_req:
            logger.warning(f"Rate limit approached: {request_count}/{max_req}")
            return False
        return True
