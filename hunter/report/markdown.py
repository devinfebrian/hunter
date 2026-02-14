"""Markdown report generator for Hunter"""

import os
from datetime import datetime
from typing import List

from hunter.models import Finding, ScanSession
from hunter.config import settings


class MarkdownReporter:
    """Generate Markdown reports for findings"""
    
    def __init__(self):
        self.output_dir = settings.output_dir
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate(self, session: ScanSession) -> str:
        """Generate markdown report for a scan session"""
        
        confirmed_findings = session.get_confirmed_findings()
        
        report_lines = [
            self._generate_header(session),
            self._generate_summary(session, confirmed_findings),
            self._generate_findings(confirmed_findings),
            self._generate_appendix(session),
        ]
        
        report = "\n".join(report_lines)
        
        # Save to file
        filename = f"hunter_report_{session.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report)
        
        return filepath
    
    def _generate_header(self, session: ScanSession) -> str:
        """Generate report header"""
        return f"""# Hunter Security Assessment Report

**Target:** {session.target.domain}  
**Scan ID:** {session.id}  
**Date:** {session.start_time.strftime('%Y-%m-%d %H:%M UTC')}  
**Duration:** {self._format_duration(session)}  

---

"""
    
    def _generate_summary(self, session: ScanSession, findings: List[Finding]) -> str:
        """Generate executive summary"""
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            # Handle both enum and string (due to use_enum_values)
            sev = f.severity.value if hasattr(f.severity, 'value') else f.severity
            severity_counts[sev] += 1
        
        return f"""## Executive Summary

This security assessment was conducted on **{session.target.domain}** using the Hunter autonomous bug bounty agent.

### Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity_counts['critical']} |
| 🟠 High | {severity_counts['high']} |
| 🟡 Medium | {severity_counts['medium']} |
| 🔵 Low | {severity_counts['low']} |
| ⚪ Info | {severity_counts['info']} |
| **Total** | **{len(findings)}** |

### Scope

- **In-Scope:** {', '.join([r.pattern for r in session.target.scope_rules if r.include]) or session.target.domain}
- **Out-of-Scope:** {', '.join([r.pattern for r in session.target.scope_rules if not r.include]) or 'None specified'}

---

"""
    
    def _generate_findings(self, findings: List[Finding]) -> str:
        """Generate detailed findings section"""
        
        if not findings:
            return "## Findings\n\nNo vulnerabilities were confirmed during this assessment.\n\n---\n\n"
        
        sections = ["## Detailed Findings\n"]
        
        for i, finding in enumerate(findings, 1):
            # Handle both enum and string
            sev = finding.severity.value if hasattr(finding.severity, 'value') else finding.severity
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }.get(sev, "⚪")
            
            sections.append(f"""### {i}. {finding.title}

| Attribute | Value |
|-----------|-------|
| **Severity** | {severity_emoji} {sev.upper()} |
| **Type** | {finding.vulnerability_type.value.upper() if hasattr(finding.vulnerability_type, 'value') else finding.vulnerability_type.upper()} |
| **URL** | `{finding.url}` |
| **Parameter** | `{finding.parameter or 'N/A'}` |
| **Status** | {'Confirmed' if finding.confirmed else 'Unconfirmed'} |

#### Description

{finding.description}

#### Impact

{finding.impact}

#### Evidence

```
{finding.evidence[:800]}{'...' if len(finding.evidence) > 800 else ''}
```

#### Proof of Concept

```bash
{finding.proof_of_concept or 'N/A'}
```

#### Remediation

{finding.remediation}

---

""")
        
        return "\n".join(sections)
    
    def _generate_appendix(self, session: ScanSession) -> str:
        """Generate appendix with methodology"""
        return f"""## Appendix

### Methodology

This assessment was conducted using the Hunter autonomous security testing framework with the following stages:

1. **Reconnaissance** - Subdomain enumeration and service discovery
2. **Vulnerability Analysis** - Automated SQL injection detection
3. **Safety Validation** - Risk assessment and approval gates
4. **Reporting** - Consolidated findings with remediation guidance

### Tools Used

- Hunter v0.1.0 (Autonomous Agent)
- Subfinder / Assetfinder (Subdomain enumeration)
- HTTPx (HTTP probing)
- Kimi K2.5 (AI-powered analysis)

### Limitations

- Testing was limited to in-scope targets only
- No destructive operations were performed
- Rate limiting was applied to minimize impact
- Some findings may require manual verification

### Disclaimer

This report contains confidential security information. Distribution should be limited to authorized personnel only. The findings represent a point-in-time assessment and may not reflect the current security posture of the target system.

---

*Report generated by Hunter - Autonomous Bug Bounty Agent*
*Session ID: {session.id}*
"""
    
    def _format_duration(self, session: ScanSession) -> str:
        """Format scan duration"""
        end = session.end_time or datetime.utcnow()
        duration = end - session.start_time
        
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
