"""Agent coordination - prevent redundant testing across agents"""

import logging
from typing import Set, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TestedParam:
    """Represents a tested parameter"""
    normalized_url: str
    parameter: str
    vuln_type: Optional[str] = None  # 'sqli', 'xss', etc.


class ScanCoordinator:
    """
    Coordinates multiple agents to avoid redundant testing.
    
    When SQLi agent finds a vulnerability in parameter 'uid',
    XSS agent will skip testing that same parameter.
    """
    
    def __init__(self):
        # Set of (normalized_url, parameter) tuples that have confirmed findings
        self._confirmed_vulnerable: Set[Tuple[str, str]] = set()
        
        # Track what each agent found for reporting
        self._findings_by_agent: dict = {}
    
    def is_tested(self, url: str, parameter: str) -> bool:
        """Check if this URL+parameter already has a confirmed finding"""
        key = self._normalize(url, parameter)
        return key in self._confirmed_vulnerable
    
    def mark_tested(self, url: str, parameter: str, vuln_type: str):
        """Mark this URL+parameter as having a confirmed finding"""
        key = self._normalize(url, parameter)
        if key not in self._confirmed_vulnerable:
            self._confirmed_vulnerable.add(key)
            logger.info(f"[Coordinator] {vuln_type.upper()} found in {parameter} at {url} - other agents will skip")
    
    def get_skip_summary(self) -> str:
        """Get summary of skipped parameters"""
        if not self._confirmed_vulnerable:
            return "No parameters skipped"
        return f"{len(self._confirmed_vulnerable)} parameter(s) will be skipped by subsequent agents"
    
    def _normalize(self, url: str, parameter: str) -> Tuple[str, str]:
        """Normalize URL and parameter for comparison"""
        # Remove protocol
        url = url.lower().replace('https://', '').replace('http://', '')
        # Remove www
        url = url.replace('www.', '')
        # Remove query string for base URL comparison
        url = url.split('?')[0].rstrip('/')
        return (url, parameter.lower().strip())
