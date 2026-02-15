"""XSS Detection logic for Hunter"""

import re
from typing import Optional, Tuple
from urllib.parse import unquote


class XSSDetector:
    """Detects XSS vulnerabilities in responses"""
    
    # XSS indicators in response
    XSS_INDICATORS = [
        r'<script>\s*alert\s*\(\s*[\'"\d]',
        r'onerror\s*=\s*[\'"]*\s*alert',
        r'onload\s*=\s*[\'"]*\s*alert',
        r'<svg[^>]*onload\s*=',
        r'<img[^>]*onerror\s*=',
        r'javascript:\s*alert',
    ]
    
    # Reflection indicators
    REFLECTION_PATTERNS = [
        r'<script[^>]*>[^<]*</script>',
        r'on\w+\s*=\s*["\']?[^"\'>\s]+',
        r'<iframe[^>]*src\s*=\s*["\']?javascript:',
        r'<object[^>]*data\s*=\s*["\']?javascript:',
    ]
    
    @staticmethod
    def detect_reflection(content: str, payload: str) -> Tuple[bool, Optional[str]]:
        """Detect if payload is reflected in content
        
        Returns:
            Tuple of (is_reflected, context)
        """
        # Normalize content for searching
        content_lower = content.lower()
        payload_lower = payload.lower()
        
        # Check direct reflection
        if payload_lower in content_lower:
            # Determine context
            context = XSSDetector._determine_context(content, payload)
            return True, context
        
        # Check URL-decoded reflection
        decoded_payload = unquote(payload)
        if decoded_payload.lower() in content_lower:
            context = XSSDetector._determine_context(content, decoded_payload)
            return True, context
        
        # Check HTML-encoded reflection
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload.lower() in content_lower:
            return True, "encoded"
        
        return False, None
    
    @staticmethod
    def _determine_context(content: str, payload: str) -> str:
        """Determine the context of XSS reflection"""
        # Find where payload appears
        idx = content.lower().find(payload.lower())
        if idx == -1:
            return "unknown"
        
        # Check surrounding context
        surrounding = content[max(0, idx-100):min(len(content), idx+len(payload)+100)]
        surrounding_lower = surrounding.lower()
        
        # Check for script context
        if '<script' in surrounding_lower and '</script>' in surrounding_lower:
            return "script"
        
        # Check for attribute context
        if surrounding.count('"') % 2 == 1 or surrounding.count("'") % 2 == 1:
            return "attribute"
        
        # Check for tag context
        if '<' in surrounding and '>' in surrounding:
            return "tag"
        
        return "html"
    
    @staticmethod
    def detect_xss_execution(content: str) -> Tuple[bool, Optional[str]]:
        """Detect if XSS payload was executed
        
        Returns:
            Tuple of (executed, evidence)
        """
        for pattern in XSSDetector.XSS_INDICATORS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return True, match.group(0)
        
        return False, None
    
    @staticmethod
    def calculate_risk_score(reflected: bool, context: str, executed: bool) -> int:
        """Calculate XSS risk score (0-100)"""
        score = 0
        
        if reflected:
            score += 30
            
            # Context adds risk
            context_scores = {
                'script': 40,
                'attribute': 30,
                'tag': 25,
                'html': 20,
                'encoded': 10,
            }
            score += context_scores.get(context, 10)
        
        if executed:
            score += 30  # Confirmed execution
        
        return min(score, 100)
    
    @staticmethod
    def is_properly_encoded(content: str, payload: str) -> bool:
        """Check if payload is properly encoded/sanitized"""
        # If dangerous chars are encoded, it's likely safe
        dangerous_chars = ['<', '>', '"', "'", '(', ')', ';']
        
        for char in dangerous_chars:
            if char in payload:
                # Check if encoded in content
                encoded = char.replace('<', '&lt;').replace('>', '&gt;')
                if encoded in content:
                    continue
                # Not encoded = potentially dangerous
                return False
        
        return True


class ResponseAnalyzer:
    """Analyzes HTTP responses for XSS indicators"""
    
    def __init__(self):
        self.detector = XSSDetector()
    
    def analyze(self, content: str, payload: str) -> dict:
        """Analyze response for XSS vulnerability
        
        Returns dict with analysis results
        """
        results = {
            'reflected': False,
            'context': None,
            'executed': False,
            'evidence': None,
            'risk_score': 0,
            'properly_encoded': True,
        }
        
        # Check reflection
        reflected, context = self.detector.detect_reflection(content, payload)
        if reflected:
            results['reflected'] = True
            results['context'] = context
        
        # Check execution
        executed, evidence = self.detector.detect_xss_execution(content)
        if executed:
            results['executed'] = True
            results['evidence'] = evidence
        
        # Check encoding
        results['properly_encoded'] = self.detector.is_properly_encoded(content, payload)
        
        # Calculate risk
        results['risk_score'] = self.detector.calculate_risk_score(
            reflected, context, executed
        )
        
        return results
