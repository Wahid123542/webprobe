# webprobe

A Python web application vulnerability scanner. Crawls a target domain and tests for common OWASP Top 10 vulnerabilities, then generates an HTML report with findings, evidence, and remediation advice.

## What it checks

- **Reflected XSS** — injects payloads into form inputs and checks for reflection
- **SQL Injection** — error-based detection on forms and URL parameters
- **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more
- **Open Redirects** — probes common redirect parameters with a canary URL

## Installation

```bash
git clone https://github.com/Wahid123542/webprobe.git
cd webprobe
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py http://target.com
python scanner.py http://target.com --depth 3 --output results.html --timeout 10
```

| Flag | Default | Description |
|---|---|---|
| `--depth` | `2` | Crawl depth |
| `--output` | `report.html` | HTML report filename |
| `--timeout` | `8` | Request timeout (seconds) |

## Test targets

These are intentionally vulnerable apps built for this purpose:

```bash
python scanner.py http://testphp.vulnweb.com

# Or run DVWA locally
docker run -p 80:80 vulnerables/web-dvwa
python scanner.py http://localhost
```

## Disclaimer

For authorized security testing only. Only scan systems you own or have explicit permission to test.

## Author

Wahid Sultani — [github.com/Wahid123542](https://github.com/Wahid123542)
