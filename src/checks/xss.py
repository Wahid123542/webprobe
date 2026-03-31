"""
XSS Scanner - tests form inputs for reflected cross-site scripting
"""

from src.utils import safe_get, safe_post, print_status

# Payloads designed to detect reflection without actually executing in reports
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    '<iframe src="javascript:alert(1)">',
]

# Markers we look for in the response to confirm reflection
REFLECTION_MARKERS = [
    "<script>alert",
    "onerror=alert",
    "onload=alert",
    "javascript:alert",
    "<iframe src=\"javascript",
]


class XSSScanner:
    def __init__(self, timeout=8):
        self.timeout = timeout

    def scan(self, forms):
        findings = []

        for form in forms:
            if not form["inputs"]:
                continue

            for payload in XSS_PAYLOADS:
                result = self._test_form(form, payload)
                if result:
                    findings.append(result)
                    # One finding per form is enough
                    break

        return findings

    def _test_form(self, form, payload):
        # Build data dict — inject payload into every text-like field
        data = {}
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "image", "reset", "hidden"):
                data[inp["name"]] = inp["value"]
            else:
                data[inp["name"]] = payload

        if form["method"] == "post":
            resp = safe_post(form["action_url"], data, self.timeout)
        else:
            resp = safe_get(form["action_url"], self.timeout, params=data)

        if resp is None:
            return None

        body = resp.text.lower()
        for marker in REFLECTION_MARKERS:
            if marker.lower() in body:
                print_status(
                    f"XSS reflected on {form['action_url']} (payload: {payload[:40]})",
                    "vuln"
                )
                return {
                    "type": "XSS",
                    "severity": "HIGH",
                    "url": form["action_url"],
                    "page": form["page_url"],
                    "detail": f"Payload reflected in response: {payload[:60]}",
                    "evidence": f"Marker '{marker}' found in response body",
                    "remediation": (
                        "Encode all user-supplied input before rendering in HTML. "
                        "Use Content-Security-Policy headers. "
                        "Prefer textContent over innerHTML."
                    ),
                }
        return None
