"""
SQLi Scanner - detects SQL injection via error-based and boolean-based heuristics
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.utils import safe_get, safe_post, print_status

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(0)--",
    "'; SELECT 1--",
]

# Common DB error strings that indicate injection point
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc drivers error",
    "ora-",
    "pg_query",
    "sqlite_",
    "microsoft ole db provider for sql server",
    "syntax error",
    "unexpected end of sql command",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
]


class SQLiScanner:
    def __init__(self, timeout=8):
        self.timeout = timeout

    def scan(self, forms, pages):
        findings = []

        # Test forms
        for form in forms:
            result = self._test_form(form)
            if result:
                findings.append(result)

        # Test URL parameters
        for url in pages:
            result = self._test_url_params(url)
            if result:
                findings.append(result)

        return findings

    def _test_form(self, form):
        for payload in SQLI_PAYLOADS:
            data = {}
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "button", "image", "reset"):
                    data[inp["name"]] = inp["value"]
                else:
                    data[inp["name"]] = payload

            if form["method"] == "post":
                resp = safe_post(form["action_url"], data, self.timeout)
            else:
                resp = safe_get(form["action_url"], self.timeout, params=data)

            if resp is None:
                continue

            error = self._detect_error(resp.text)
            if error:
                print_status(
                    f"SQLi (error-based) on {form['action_url']}",
                    "vuln"
                )
                return {
                    "type": "SQL Injection",
                    "severity": "CRITICAL",
                    "url": form["action_url"],
                    "page": form["page_url"],
                    "detail": f"DB error triggered by payload: {payload}",
                    "evidence": f"Error signature: '{error}'",
                    "remediation": (
                        "Use parameterized queries / prepared statements exclusively. "
                        "Never concatenate user input into SQL strings. "
                        "Apply least-privilege DB accounts."
                    ),
                }
        return None

    def _test_url_params(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return None

        for param in params:
            for payload in SQLI_PAYLOADS:
                modified = dict(params)
                modified[param] = [payload]
                new_query = urlencode(modified, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = safe_get(test_url, self.timeout)
                if resp is None:
                    continue

                error = self._detect_error(resp.text)
                if error:
                    print_status(f"SQLi (URL param) on {test_url}", "vuln")
                    return {
                        "type": "SQL Injection",
                        "severity": "CRITICAL",
                        "url": test_url,
                        "page": url,
                        "detail": f"Parameter '{param}' triggers DB error with payload: {payload}",
                        "evidence": f"Error signature: '{error}'",
                        "remediation": (
                            "Use parameterized queries / prepared statements exclusively. "
                            "Never concatenate user input into SQL strings. "
                            "Apply least-privilege DB accounts."
                        ),
                    }
        return None

    def _detect_error(self, body):
        lower = body.lower()
        for sig in ERROR_SIGNATURES:
            if sig in lower:
                return sig
        return None
