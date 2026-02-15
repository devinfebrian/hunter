"""SQL Injection detection logic for Hunter"""

import re
from typing import Optional, Tuple, List
from playwright.async_api import Page

from hunter.agents.sqli.payloads import SQL_ERROR_PATTERNS


class SQLiDetector:
    """Detects SQL injection vulnerabilities in responses"""
    
    @staticmethod
    def detect_sql_error(content: str) -> Tuple[Optional[str], Optional[str]]:
        """Detect SQL error patterns in content
        
        Returns:
            Tuple of (database_type, error_context) or (None, None)
        """
        for db_type, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    # Extract context around the error (increased for better evidence)
                    start = max(0, match.start() - 200)
                    end = min(len(content), match.end() + 800)
                    return db_type, content[start:end]
        return None, None
    
    @staticmethod
    async def detect_auth_success(page: Page, before_url: str, after_url: str) -> bool:
        """Detect if authentication was successful
        
        Checks for:
        - URL changed away from login page
        - Logout/Sign Off links appeared
        - Welcome messages
        - Account-related content
        """
        if "login" not in before_url.lower():
            return False
        
        # Failed login often redirects to search/error pages
        failure_indicators = ['search', 'error', 'fail', 'invalid', 'incorrect']
        if any(x in after_url.lower() for x in failure_indicators):
            return False
        
        # Get page content
        try:
            page_text = await page.inner_text("body")
            page_lower = page_text.lower()
        except:
            return False
        
        # Success indicators
        success_indicators = [
            "logout", "sign out", "log out", "sign off",
            "my account", "welcome back", "dashboard",
            "hello admin", "account summary", "profile"
        ]
        
        for indicator in success_indicators:
            if indicator in page_lower:
                return True
        
        # Check for logout link
        try:
            logout_selectors = [
                "a[href*='logout']",
                "a[href*='signout']",
                "a:has-text('Sign Off')",
                "a:has-text('Log Out')"
            ]
            for selector in logout_selectors:
                elem = await page.query_selector(selector)
                if elem:
                    return True
        except:
            pass
        
        return False
    
    @staticmethod
    def detect_boolean_blind(response_text: str, baseline_text: str) -> bool:
        """Detect boolean-based blind SQL injection
        
        Compares responses to detect differences that indicate SQLi
        """
        len_diff = abs(len(response_text) - len(baseline_text))
        if len_diff > 500:
            return True
        
        # Could add more sophisticated checks here
        # like comparing specific DOM elements
        
        return False


class ResponseAnalyzer:
    """Analyzes HTTP responses for vulnerability indicators"""
    
    def __init__(self):
        self.detector = SQLiDetector()
    
    def analyze(self, content: str, baseline_content: Optional[str] = None) -> dict:
        """Analyze response content for vulnerabilities
        
        Returns dict with findings
        """
        results = {
            'sql_error': None,
            'error_db_type': None,
            'error_context': None,
        }
        
        # Check for SQL errors
        db_type, error_msg = self.detector.detect_sql_error(content)
        if db_type:
            results['sql_error'] = True
            results['error_db_type'] = db_type
            results['error_context'] = error_msg
        
        return results
