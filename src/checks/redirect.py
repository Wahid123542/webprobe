"""
Open Redirect Scanner - detects unvalidated redirect parameters in URLs
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.utils import safe_get, print_status

# Common redirect parameter names
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "returnTo",
    "return_url", "next", "url", "goto", "target", "destination",
    "redir", "continue", "forward", "location", "link", "to",
]

CANARY = "https://evil.example.com"


class RedirectScanner:
    def __init__(self, timeout=8):
        self.timeout = timeout

    def scan(self, pages):
        findings = []
        seen = set()

        for url in pages:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Check existing redirect-like params in the URL
            for param in list(params.keys()):
                if param.lower() in [r.lower() for r in REDIRECT_PARAMS]:
                    key = f"{parsed.netloc}{parsed.path}:{param}"
                    if key in seen:
                        continue
                    seen.add(key)

                    result = self._test_param(url, parsed, params, param)
                    if result:
                        findings.append(result)

            # Also probe known redirect param names even if not in URL
            for rp in REDIRECT_PARAMS:
                if rp not in params:
                    key = f"{parsed.netloc}{parsed.path}:{rp}"
                    if key in seen:
                        continue
                    seen.add(key)

                    test_params = dict(params)
                    test_params[rp] = [CANARY]
                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    resp = safe_get(test_url, self.timeout, allow_redirects=False)
                    if resp and self._is_redirect_to_canary(resp):
                        print_status(f"Open redirect via '{rp}' on {url}", "vuln")
                        findings.append({
                            "type": "Open Redirect",
                            "severity": "MEDIUM",
                            "url": test_url,
                            "page": url,
                            "detail": f"Parameter '{rp}' redirects to attacker-controlled URL",
                            "evidence": f"HTTP {resp.status_code} → Location: {resp.headers.get('Location', '')}",
                            "remediation": (
                                "Validate redirect targets against an allowlist of trusted domains. "
                                "Never redirect to a URL supplied directly by user input."
                            ),
                        })

        return findings

    def _test_param(self, url, parsed, params, param):
        modified = dict(params)
        modified[param] = [CANARY]
        new_query = urlencode(modified, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        resp = safe_get(test_url, self.timeout, allow_redirects=False)
        if resp and self._is_redirect_to_canary(resp):
            print_status(f"Open redirect via '{param}' on {url}", "vuln")
            return {
                "type": "Open Redirect",
                "severity": "MEDIUM",
                "url": test_url,
                "page": url,
                "detail": f"Parameter '{param}' redirects to attacker-controlled URL",
                "evidence": f"HTTP {resp.status_code} → Location: {resp.headers.get('Location', '')}",
                "remediation": (
                    "Validate redirect targets against an allowlist of trusted domains. "
                    "Never redirect to a URL supplied directly by user input."
                ),
            }
        return None

    def _is_redirect_to_canary(self, resp):
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if CANARY in location:
                return True
        return False
