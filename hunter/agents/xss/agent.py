"""XSS Agent for Hunter - Cross-Site Scripting Detection"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import parse_qs, urlencode, urlunparse, urlparse

import httpx
from playwright.async_api import Page

from hunter.models import Endpoint, Finding, VulnType, Severity
from hunter.agents.base import BaseAgent
from hunter.agents.xss.payloads import get_payloads, get_context_for_payload
from hunter.agents.xss.detectors import XSSDetector, ResponseAnalyzer
from hunter.crawler.browser_crawler import BrowserCrawler

logger = logging.getLogger(__name__)


class XSSAgent(BaseAgent):
    """Browser-based Cross-Site Scripting detection agent"""
    
    NAME = "xss_agent"
    VULN_TYPE = "xss"
    
    # Limits to prevent scan from taking too long
    MAX_FORMS_PER_PAGE = 5      # Test first 5 forms
    MAX_FIELDS_PER_FORM = 6     # Test first 6 text fields
    
    def __init__(self, coordinator=None):
        super().__init__(coordinator)
        self.crawler: Optional[BrowserCrawler] = None
        self.detector = XSSDetector()
        self.analyzer = ResponseAnalyzer()
        self.browser = None
    
    async def _setup(self):
        """Initialize browser and crawler"""
        self.crawler = BrowserCrawler(delay=self.rate_limiter.delay)
        await self.crawler.__aenter__()
        self.browser = self.crawler.browser
        logger.info(f"XSSAgent: Fresh browser initialized (clean session)")
    
    async def _teardown(self):
        """Cleanup browser and crawler"""
        if self.crawler:
            await self.crawler.__aexit__(None, None, None)
    
    async def analyze(self, endpoint: Endpoint) -> List[Finding]:
        """Analyze endpoint for XSS vulnerabilities"""
        logger.info(f"XSS analysis: {endpoint.url}")
        
        # Test 1: URL parameters (GET requests) - Reflected XSS
        await self._test_url_parameters(endpoint.url)
        
        # Test 2: Forms on main page - Stored/Reflected XSS
        await self._test_page_forms(endpoint.url)
        
        # Test 3: Discover and test additional pages
        await self._test_discovered_pages(endpoint.url)
        
        return self.findings
    
    async def _test_url_parameters(self, url: str) -> None:
        """Test URL query parameters for Reflected XSS"""
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        if not params:
            return
        
        # Filter out already-tested parameters
        untested_params = [p for p in params.keys() if not self._should_skip_param(url, p)]
        if not untested_params:
            logger.info(f"All URL parameters already tested by other agents, skipping")
            return
        
        logger.info(f"Testing {len(untested_params)} URL parameter(s) for XSS: {untested_params}")
        
        async with httpx.AsyncClient(follow_redirects=True, timeout=30, verify=False) as client:
            for param_name in untested_params:
                await self._test_param_http(client, url, param_name, params)
    
    async def _test_param_http(self, client: httpx.AsyncClient, url: str,
                               param_name: str, original_params: Dict) -> None:
        """Test a single parameter via HTTP for Reflected XSS"""
        # Use payloads likely to show reflection
        payloads = get_payloads("basic") + get_payloads("img")
        
        for payload in payloads:
            try:
                await self.rate_limiter.acquire()
                
                # Inject payload
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(urlparse(url)._replace(query=new_query))
                
                response = await client.get(test_url)
                
                # Analyze response
                analysis = self.analyzer.analyze(response.text, payload)
                
                if analysis['reflected'] and not analysis['properly_encoded']:
                    # Potential XSS found
                    logger.info(f"[FOUND] Reflected XSS in URL param '{param_name}'")
                    
                    finding = self._create_finding(
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        context=analysis['context'],
                        evidence=f"Payload reflected in {analysis['context']} context",
                        method="GET",
                        xss_type="Reflected"
                    )
                    self._add_finding(finding)
                    return
                    
            except Exception as e:
                logger.debug(f"Param test error: {e}")
    
    async def _test_page_forms(self, url: str) -> None:
        """Test forms on a page (with limits)"""
        page_data = await self.crawler.crawl_page(url)
        if not page_data:
            return
        
        forms_to_test = page_data.forms[:self.MAX_FORMS_PER_PAGE]
        if len(page_data.forms) > self.MAX_FORMS_PER_PAGE:
            logger.info(f"Limiting to {self.MAX_FORMS_PER_PAGE} forms (found {len(page_data.forms)})")
        
        for form in forms_to_test:
            await self._test_form(url, form)
    
    async def _test_discovered_pages(self, base_url: str) -> None:
        """Discover and test additional pages"""
        # Find search pages, comment forms, etc.
        page_data = await self.crawler.crawl_page(base_url)
        if not page_data:
            return
        
        # Look for interesting links
        interesting_keywords = ['search', 'comment', 'feedback', 'contact', 'profile']
        
        for link in page_data.links:
            href = link.get('href', '')
            text = link.get('text', '').lower()
            
            is_interesting = any(kw in href.lower() or kw in text for kw in interesting_keywords)
            
            if is_interesting:
                logger.info(f"Testing interesting page: {href}")
                await self._test_page_forms(href)
    
    async def _test_form(self, base_url: str, form) -> None:
        """Test a single form for XSS (with field limits)"""
        form_url = self._resolve_url(base_url, form.action) if form.action else base_url
        
        # Count text fields only
        text_fields = [f for f in form.inputs 
                      if f.get('type', 'text') in ['text', 'email', 'search', 'password', 'textarea', '']]
        
        fields_to_test = text_fields[:self.MAX_FIELDS_PER_FORM]
        if len(text_fields) > self.MAX_FIELDS_PER_FORM:
            logger.info(f"Limiting to {self.MAX_FIELDS_PER_FORM} fields (found {len(text_fields)})")
        
        logger.info(f"Testing form: {form_url} ({form.method}) with {len(fields_to_test)}/{len(text_fields)} field(s)")
        
        for input_field in fields_to_test:
            await self._test_form_field(form_url, form, input_field)
    
    async def _test_form_field(self, form_url: str, form, input_field: Dict) -> None:
        """Test a single form field with XSS payloads"""
        field_name = input_field['name']
        field_type = input_field.get('type', 'text')
        
        # Skip non-text fields
        if field_type not in ['text', 'email', 'search', 'password', 'textarea', '']:
            return
        
        # Skip if already tested by another agent (e.g., SQLi found it first)
        if self._should_skip_param(form_url, field_name):
            return
        
        # Get payloads - use diverse set for forms
        payloads = (get_payloads("basic") + 
                   get_payloads("img") + 
                   get_payloads("event_handlers"))
        
        for payload in payloads:
            try:
                finding = await self._submit_and_check(form_url, form, input_field, payload)
                if finding:
                    self._add_finding(finding)
                    return
            except Exception as e:
                logger.debug(f"Form test error for {field_name}: {e}")
                continue
    
    async def _submit_and_check(self, form_url: str, form, input_field: Dict,
                                payload: str) -> Optional[Finding]:
        """Submit form with payload and check for XSS"""
        from playwright.async_api import Error as PlaywrightError
        
        field_name = input_field['name']
        
        page = None
        try:
            page = await self.browser.new_page()
            await self.rate_limiter.acquire()
            
            # Load fresh page (navigate to form page) - use shorter timeout
            try:
                await page.goto(form_url, wait_until="domcontentloaded", timeout=15000)
            except PlaywrightError as e:
                # Handle navigation errors (ERR_ABORTED, timeout, etc.)
                error_msg = str(e).lower()
                if 'err_aborted' in error_msg or 'net::' in error_msg:
                    logger.debug(f"Navigation aborted for {form_url}: {e}")
                else:
                    logger.debug(f"Navigation error for {form_url}: {e}")
                return None
            
            # Prepare field values
            field_values = {field_name: payload}
            
            # Fill other fields
            for other in form.inputs:
                if other['name'] != field_name:
                    dummy = "test@example.com" if other.get('type') == 'email' else "testuser"
                    field_values[other['name']] = dummy
            
            # Submit form and capture response
            result_page = await self.crawler.submit_form(page, form, field_values)
            if not result_page:
                return None
            
            await asyncio.sleep(0.2)  # Short wait for JS (reduced from 0.5s)
            
            # Check HTTP status - reject if error (4xx, 5xx)
            # Note: Playwright doesn't expose status directly, check URL or content
            current_url = result_page.url
            
            # If still on same URL with error message, form submission failed
            content = await result_page.content()
            
            # Check for common error indicators
            error_indicators = ['405', 'method not allowed', 'error', 'failed', 'not supported']
            has_error = any(ind in content.lower() for ind in error_indicators)
            
            if has_error and '405' in content:
                logger.debug(f"Form submission returned 405 for {form_url}")
                return None
            
            # Analyze for XSS
            analysis = self.analyzer.analyze(content, payload)
            
            if analysis['reflected'] and not analysis['properly_encoded']:
                # Determine XSS type
                xss_type = "Stored" if form.method.lower() == "post" else "Reflected"
                
                logger.info(f"[FOUND] {xss_type} XSS in field '{field_name}'")
                
                # Build better evidence with full payload context
                evidence = self._build_evidence(content, payload, analysis)
                
                return self._create_finding(
                    url=form_url,
                    parameter=field_name,
                    payload=payload,
                    context=analysis['context'],
                    evidence=evidence,
                    method=form.method.upper(),
                    xss_type=xss_type
                )
            
        except Exception as e:
            logger.debug(f"Form test error for '{field_name}': {e}")
        finally:
            if page:
                try:
                    await page.close()
                except:
                    pass
        
        return None
    
    def _build_evidence(self, content: str, payload: str, analysis: dict) -> str:
        """Build detailed evidence showing payload reflection"""
        import re
        
        # Find the payload in content
        idx = content.find(payload)
        if idx == -1:
            # Try case-insensitive
            idx = content.lower().find(payload.lower())
        
        if idx == -1:
            return analysis.get('evidence') or f"Payload reflected in {analysis['context']} context"
        
        # Extract context around the payload (more generous window)
        start = max(0, idx - 300)
        end = min(len(content), idx + len(payload) + 300)
        
        context = content[start:end]
        
        # Highlight the payload
        highlighted = context.replace(payload, f"***{payload}***")
        
        # Build evidence string
        evidence_parts = [
            f"Context: {analysis['context']}",
            f"Risk Score: {analysis.get('risk_score', 'unknown')}",
            "",
            "Reflected Payload:",
            "---",
            highlighted,
            "---"
        ]
        
        return "\n".join(evidence_parts)
    
    def _create_finding(self, url: str, parameter: str, payload: str,
                        context: str, evidence: str, method: str,
                        xss_type: str = "Reflected") -> Finding:
        """Create a Finding object for XSS"""
        
        # Severity based on context
        severity = Severity.HIGH if context in ['script', 'attribute'] else Severity.MEDIUM
        
        if xss_type == "Stored":
            severity = Severity.HIGH  # Stored XSS is always high
        
        if method == "GET":
            poc = f'curl -X GET "{url}?{parameter}={payload}"'
        else:
            poc = f'curl -X POST "{url}" -d "{parameter}={payload}"'
        
        return Finding(
            vulnerability_type=VulnType.XSS,
            severity=severity,
            url=url,
            parameter=parameter,
            method=method,
            payload=payload,
            evidence=evidence[:1000],
            proof_of_concept=poc,
            title=f"{xss_type} XSS in '{parameter}' field ({context} context)",
            description=f"{xss_type} Cross-Site Scripting vulnerability detected in '{parameter}' "
                       f"via {method} request. Payload executes in {context} context.",
            impact="Attackers can execute JavaScript in victim's browser, steal cookies, "
                   "session tokens, or perform actions on behalf of the user.",
            remediation="Encode all user input before output. Use Content Security Policy (CSP). "
                       "Implement proper input validation and output encoding.",
            discovered_by=self.NAME
        )
