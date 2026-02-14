"""HTTP probing module for Hunter"""

import asyncio
import logging
from typing import List, Dict
from dataclasses import dataclass
import httpx

from hunter.config import settings
from hunter.models import Endpoint

logger = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    url: str
    status_code: int
    title: str = ""
    content_length: int = 0
    server: str = ""
    technology: str = ""


class HTTPProber:
    """Probe HTTP endpoints for live services"""
    
    def __init__(self):
        self.delay = settings.delay_between_requests
        self.max_concurrent = 50
        self.timeout = httpx.Timeout(10.0, connect=5.0)
    
    async def probe(self, urls: List[str]) -> List[Endpoint]:
        """Probe a list of URLs and return live endpoints"""
        logger.info(f"Probing {len(urls)} URLs")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = [u for u in urls if not (u in seen or seen.add(u))]
        
        # Create semaphore for rate limiting
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Probe all URLs concurrently
        tasks = [self._probe_single(url, semaphore) for url in unique_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful probes
        endpoints = []
        for result in results:
            if isinstance(result, Exception):
                continue
            if result and result.status_code > 0:
                endpoints.append(self._result_to_endpoint(result))
        
        logger.info(f"Found {len(endpoints)} live endpoints")
        return endpoints
    
    async def _probe_single(self, url: str, semaphore: asyncio.Semaphore) -> ProbeResult:
        """Probe a single URL"""
        async with semaphore:
            try:
                # Ensure URL has scheme
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}"
                
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False  # Allow self-signed certs for testing
                ) as client:
                    response = await client.get(url)
                    
                    # Parse response
                    title = self._extract_title(response.text)
                    server = response.headers.get("server", "")
                    
                    result = ProbeResult(
                        url=str(response.url),
                        status_code=response.status_code,
                        title=title,
                        content_length=len(response.content),
                        server=server,
                        technology=self._detect_tech(response.headers, response.text)
                    )
                    
                    # Rate limiting delay
                    await asyncio.sleep(self.delay)
                    
                    return result
                    
            except httpx.TimeoutException:
                logger.debug(f"Timeout probing {url}")
                return ProbeResult(url=url, status_code=0)
            except Exception as e:
                logger.debug(f"Error probing {url}: {e}")
                return ProbeResult(url=url, status_code=0)
    
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        import re
        
        title_match = re.search(r'<title[^>]*>([^<]*)</title>', html, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()
        return ""
    
    def _detect_tech(self, headers: Dict[str, str], body: str) -> str:
        """Detect technology from headers and body"""
        tech_signatures = {
            "Apache": ["Apache", "apache"],
            "Nginx": ["nginx", "Nginx"],
            "Cloudflare": ["cloudflare", "cf-ray"],
            "PHP": ["PHP", "php"],
            "Express": ["express", "Express"],
            "Django": ["django", "csrftoken"],
            "Rails": ["rails", "_rails"],
            "ASP.NET": ["asp.net", "ASP.NET", "X-AspNet"],
            "WordPress": ["wordpress", "wp-content", "wp-includes"],
            "React": ["react", "reactroot", "__REACT__"],
            "Vue": ["vue", "__VUE__"],
            "Angular": ["angular", "ng-"],
        }
        
        detected = []
        header_str = str(headers).lower()
        body_lower = body.lower()
        
        for tech, signatures in tech_signatures.items():
            for sig in signatures:
                if sig.lower() in header_str or sig.lower() in body_lower[:5000]:
                    detected.append(tech)
                    break
        
        return ", ".join(detected[:3])  # Return top 3 matches
    
    def _result_to_endpoint(self, result: ProbeResult) -> Endpoint:
        """Convert ProbeResult to Endpoint model"""
        return Endpoint(
            url=result.url,
            method="GET",
            status_code=result.status_code,
            technology=result.technology
        )
    
    async def discover_urls(self, domain: str, subdomains: List[str]) -> List[str]:
        """Generate URLs to probe from subdomains"""
        urls = []
        
        # Add root domain
        urls.append(f"https://{domain}")
        urls.append(f"http://{domain}")
        
        # Add subdomains
        for sub in subdomains:
            urls.append(f"https://{sub}")
            urls.append(f"http://{sub}")
        
        return urls
