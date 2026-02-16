"""SQL Injection Agent for Hunter - Refactored"""

import asyncio
import logging
from typing import List, Optional, Dict
from urllib.parse import parse_qs, urlencode, urlunparse, urlparse

import httpx
from playwright.async_api import Browser, Page

from hunter.models import Endpoint, Finding, VulnType, Severity
from hunter.agents.base import BaseAgent
from hunter.agents.sqli.payloads import get_payloads, is_auth_bypass_payload
from hunter.agents.sqli.detectors import SQLiDetector
from hunter.crawler.browser_crawler import BrowserCrawler

logger = logging.getLogger(__name__)


class SQLiAgent(BaseAgent):
    """Browser-based SQL Injection detection agent"""
    
    NAME = "sqli_agent"
    VULN_TYPE = "sqli"
    
    # Limits to prevent scan from taking too long
    MAX_FORMS_PER_PAGE = 3      # Only test first 3 forms
    MAX_FIELDS_PER_FORM = 4     # Only test first 4 text fields
    MAX_PAYLOADS_PER_FIELD = 3  # Limit payloads (already optimized in payloads.py)
    
    def __init__(self, coordinator=None):
        super().__init__(coordinator)
        self.crawler: Optional[BrowserCrawler] = None
        self.detector = SQLiDetector()
        self.browser: Optional[Browser] = None
        self.forms_tested = 0     # Track forms tested per endpoint
    
    async def _setup(self):
        """Initialize browser and crawler"""
        self.crawler = BrowserCrawler(delay=self.rate_limiter.delay)
        await self.crawler.__aenter__()
        self.browser = self.crawler.browser
    
    async def _teardown(self):
        """Cleanup browser and crawler"""
        if self.crawler:
            await self.crawler.__aexit__(None, None, None)
    
    async def analyze(self, endpoint: Endpoint) -> List[Finding]:
        """Analyze endpoint for SQL injection"""
        logger.info(f"Analyzing: {endpoint.url}")
        
        # Test 1: URL parameters (GET requests)
        await self._test_url_parameters(endpoint.url)
        
        # Test 2: Forms on main page
        await self._test_page_forms(endpoint.url)
        
        # Test 3: Discover and test login pages
        await self._test_login_pages(endpoint.url)
        
        return self.findings
    
    async def _test_url_parameters(self, url: str) -> None:
        """Test URL query parameters for SQLi"""
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
        
        logger.info(f"Testing {len(untested_params)} URL parameter(s): {untested_params}")
        
        async with httpx.AsyncClient(follow_redirects=True, timeout=30, verify=False) as client:
            for param_name in untested_params:
                await self._test_param_http(client, url, param_name, params)
    
    async def _test_param_http(self, client: httpx.AsyncClient, url: str, 
                               param_name: str, original_params: Dict) -> None:
        """Test a single parameter via HTTP"""
        payloads = get_payloads("error_based")
        
        for payload in payloads:
            try:
                await self.rate_limiter.acquire()
                
                # Inject payload
                test_params = original_params.copy()
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(urlparse(url)._replace(query=new_query))
                
                response = await client.get(test_url)
                
                # Check for SQL errors
                db_type, error_msg = self.detector.detect_sql_error(response.text)
                if db_type:
                    logger.info(f"[FOUND] SQLi in URL param '{param_name}' - {db_type}")
                    
                    finding = self._create_finding(
                        url=url,
                        parameter=param_name,
                        payload=payload,
                        evidence=error_msg,
                        db_type=db_type,
                        method="GET"
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
    
    async def _test_login_pages(self, base_url: str) -> None:
        """Discover and test login pages"""
        login_urls = await self.crawler.find_login_pages(base_url)
        
        for login_url in login_urls[:3]:  # Test up to 3 login pages
            logger.info(f"Testing login page: {login_url}")
            await self._test_page_forms(login_url)
    
    async def _test_form(self, base_url: str, form) -> None:
        """Test a single form for SQLi (with field limits)"""
        from hunter.crawler.browser_crawler import FormData
        
        form_url = self._resolve_url(base_url, form.action) if form.action else base_url
        
        # Count text fields only
        text_fields = [f for f in form.inputs 
                      if f.get('type', 'text') in ['text', 'email', 'search', 'password', '']]
        
        fields_to_test = text_fields[:self.MAX_FIELDS_PER_FORM]
        if len(text_fields) > self.MAX_FIELDS_PER_FORM:
            logger.info(f"Limiting to {self.MAX_FIELDS_PER_FORM} fields (found {len(text_fields)})")
        
        logger.info(f"Testing form: {form_url} ({form.method}) with {len(fields_to_test)}/{len(text_fields)} field(s)")
        
        for input_field in fields_to_test:
            await self._test_form_field(form_url, form, input_field)
    
    async def _test_form_field(self, form_url: str, form, input_field: Dict) -> None:
        """Test a single form field with various payloads"""
        field_name = input_field['name']
        field_type = input_field.get('type', 'text')
        
        # Skip non-text fields
        if field_type not in ['text', 'email', 'search', 'password', '']:
            return
        
        # Skip if already tested by another agent
        if self._should_skip_param(form_url, field_name):
            return
        
        # Choose payloads based on field type
        is_password = field_type == 'password' or 'pass' in field_name.lower()
        
        if is_password:
            payloads = get_payloads("auth_bypass") + get_payloads("error_based")
        else:
            payloads = get_payloads("error_based") + get_payloads("auth_bypass")
        
        for payload in payloads:
            try:
                finding = await self._submit_and_check(form_url, form, input_field, payload)
                if finding:
                    self._add_finding(finding)
                    return  # Found one, move to next field
            except Exception as e:
                logger.debug(f"Form test error for {field_name}: {e}")
                continue
    
    async def _submit_and_check(self, form_url: str, form, input_field: Dict, 
                                payload: str) -> Optional[Finding]:
        """Submit form with payload and check for vulnerabilities"""
        from playwright.async_api import Error as PlaywrightError
        
        field_name = input_field['name']
        
        page = None
        try:
            page = await self.browser.new_page()
            await self.rate_limiter.acquire()
            
            # Load fresh page (navigate to form page)
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
            
            # Fill other fields with dummy data
            for other in form.inputs:
                if other['name'] != field_name:
                    dummy = "password123" if other.get('type') == 'password' else "testuser"
                    field_values[other['name']] = dummy
            
            # Capture before state
            before_url = page.url
            
            # Submit form
            result_page = await self.crawler.submit_form(page, form, field_values)
            if not result_page:
                return None
            
            await asyncio.sleep(0.2)  # Short wait for JS (reduced from 0.5s)
            
            after_url = result_page.url
            content = await result_page.content()
            
            # Check 1: Authentication bypass (PRIORITY - higher severity)
            if is_auth_bypass_payload(payload):
                is_auth_success = await self.detector.detect_auth_success(
                    result_page, before_url, after_url
                )
                if is_auth_success:
                    logger.info(f"[FOUND] Auth bypass in field '{field_name}'")
                    return self._create_finding(
                        url=form_url,
                        parameter=field_name,
                        payload=payload,
                        evidence=f"Authentication bypass successful! Redirected from {before_url} to {after_url}",
                        db_type="auth_bypass",
                        method=form.method.upper(),
                        is_auth_bypass=True
                    )
            
            # Check 2: SQL errors in response
            db_type, error_msg = self.detector.detect_sql_error(content)
            if db_type:
                logger.info(f"[FOUND] SQLi in field '{field_name}' - {db_type}")
                return self._create_finding(
                    url=form_url,
                    parameter=field_name,
                    payload=payload,
                    evidence=error_msg,
                    db_type=db_type,
                    method=form.method.upper()
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
    
    def _create_finding(self, url: str, parameter: str, payload: str,
                        evidence: str, db_type: str, method: str,
                        is_auth_bypass: bool = False) -> Finding:
        """Create a Finding object"""
        # Severity: Auth bypass = Critical, SQL error = High/Medium
        if is_auth_bypass:
            severity = Severity.CRITICAL
        elif is_auth_bypass_payload(payload):
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        
        if method == "GET":
            poc = f'curl -X GET "{url}?{parameter}={payload}"'
        else:
            poc = f'curl -X POST "{url}" -d "{parameter}={payload}"'
        
        return Finding(
            vulnerability_type=VulnType.SQLI,
            severity=severity,
            url=url,
            parameter=parameter,
            method=method,
            payload=payload,
            evidence=evidence[:1000],
            proof_of_concept=poc,
            title=f"SQL Injection in '{parameter}' field ({db_type})",
            description=f"SQL injection detected in '{parameter}' via {method}.",
            impact="Attackers can bypass authentication or manipulate database queries.",
            remediation="Use parameterized queries and input validation.",
            discovered_by=self.NAME
        )
