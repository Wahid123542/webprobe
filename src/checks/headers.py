"""
Header Scanner - checks for missing or misconfigured HTTP security headers
"""

from src.utils import safe_get, print_status

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "detail": "No Content-Security-Policy header found.",
        "remediation": "Add a strict CSP to prevent XSS and data injection attacks. "
                       "Example: Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "detail": "No X-Frame-Options header. Site may be embeddable in iframes.",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "detail": "No X-Content-Type-Options header.",
        "remediation": "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "detail": "No HSTS header. Connections may be downgraded to HTTP.",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "detail": "No Referrer-Policy header. Referrer data may leak to third parties.",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "detail": "No Permissions-Policy header. Browser features are unrestricted.",
        "remediation": "Add Permissions-Policy to restrict camera, microphone, geolocation, etc.",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Reveals server software version — aids targeted attacks.",
    "X-Powered-By": "Reveals backend technology — aids targeted attacks.",
    "X-AspNet-Version": "Reveals ASP.NET version — aids targeted attacks.",
}


class HeaderScanner:
    def __init__(self, timeout=8):
        self.timeout = timeout

    def scan(self, pages):
        findings = []
        # Only check the first 5 unique pages to avoid redundancy
        checked_origins = set()

        for url in pages[:10]:
            from urllib.parse import urlparse
            origin = urlparse(url).netloc
            if origin in checked_origins:
                continue
            checked_origins.add(origin)

            resp = safe_get(url, self.timeout)
            if resp is None:
                continue

            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check missing headers
            for header, meta in REQUIRED_HEADERS.items():
                if header.lower() not in headers:
                    print_status(f"Missing header: {header} on {url}", "warn")
                    findings.append({
                        "type": "Missing Security Header",
                        "severity": meta["severity"],
                        "url": url,
                        "page": url,
                        "detail": f"Missing: {header} — {meta['detail']}",
                        "evidence": f"Header '{header}' absent from HTTP response",
                        "remediation": meta["remediation"],
                    })

            # Check dangerous info-leaking headers
            for header, description in DANGEROUS_HEADERS.items():
                if header.lower() in headers:
                    val = headers[header.lower()]
                    print_status(f"Info-leaking header: {header}: {val} on {url}", "warn")
                    findings.append({
                        "type": "Information Disclosure",
                        "severity": "LOW",
                        "url": url,
                        "page": url,
                        "detail": f"Header '{header}: {val}' — {description}",
                        "evidence": f"{header}: {val}",
                        "remediation": f"Remove or obscure the '{header}' response header.",
                    })

        return findings
