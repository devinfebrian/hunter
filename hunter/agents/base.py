"""Base Agent class for Hunter"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import List, Optional
from urllib.parse import urljoin

from hunter.models import Endpoint, Finding
from hunter.safety.controller import SafetyController
from hunter.config import settings

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for HTTP requests"""
    
    def __init__(self, delay: Optional[float] = None):
        self.delay = delay or settings.delay_between_requests
        self.last_request = 0
    
    async def acquire(self):
        """Wait for rate limit"""
        import time
        now = time.time()
        if now - self.last_request < self.delay:
            await asyncio.sleep(self.delay - (now - self.last_request))
        self.last_request = time.time()


class BaseAgent(ABC):
    """Abstract base class for all vulnerability detection agents"""
    
    NAME: str = "base_agent"
    
    def __init__(self):
        self.safety = SafetyController()
        self.rate_limiter = RateLimiter()
        self.findings: List[Finding] = []
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._setup()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._teardown()
    
    async def _setup(self):
        """Override for agent initialization"""
        pass
    
    async def _teardown(self):
        """Override for agent cleanup"""
        pass
    
    @abstractmethod
    async def analyze(self, endpoint: Endpoint) -> List[Finding]:
        """Analyze an endpoint for vulnerabilities"""
        pass
    
    def _add_finding(self, finding: Finding) -> bool:
        """Add finding with deduplication and safety checks"""
        # Deduplication - normalize URLs for comparison
        def normalize_url(url: str) -> str:
            """Normalize URL for deduplication (remove protocol, www, default ports)"""
            url = url.lower()
            url = url.replace('https://', '').replace('http://', '')
            url = url.replace('www.', '')
            url = url.rstrip('/')
            # Remove default ports
            url = url.replace(':443', '').replace(':80', '')
            return url
        
        def normalize_param(param: Optional[str]) -> str:
            """Normalize parameter name (case-insensitive)"""
            return (param or '').lower().strip()
        
        finding_url_norm = normalize_url(finding.url)
        finding_param_norm = normalize_param(finding.parameter)
        
        for existing in self.findings:
            existing_url_norm = normalize_url(existing.url)
            existing_param_norm = normalize_param(existing.parameter)
            
            if (existing_url_norm == finding_url_norm and 
                existing_param_norm == finding_param_norm and
                existing.method.upper() == finding.method.upper() and
                existing.vulnerability_type == finding.vulnerability_type):
                logger.debug(f"Duplicate finding skipped: {finding.title}")
                return False
        
        # Safety check
        exploit_req = self.safety.assess_sql_injection(finding)
        if exploit_req.requires_approval:
            approved = self.safety.request_approval(exploit_req)
            if not approved:
                finding.status = "skipped"
                return False
        
        finding.confirmed = True
        finding.status = "confirmed"
        finding.discovered_by = self.NAME
        self.findings.append(finding)
        logger.info(f"[CONFIRMED] {finding.title}")
        return True
    
    def _resolve_url(self, base_url: str, path: str) -> str:
        """Resolve relative URL to absolute"""
        if path.startswith(('http://', 'https://')):
            return path
        return urljoin(base_url, path)
