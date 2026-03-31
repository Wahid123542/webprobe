#!/usr/bin/env python3
"""
WebProbe - Web Vulnerability Scanner
Detects: XSS, SQLi, Open Redirects, Missing Security Headers
Usage: python scanner.py <target_url> [--depth N] [--output report.html]
"""

import argparse
import sys
from src.crawler import Crawler
from src.checks.xss import XSSScanner
from src.checks.sqli import SQLiScanner
from src.checks.headers import HeaderScanner
from src.checks.redirect import RedirectScanner
from src.reporter import Reporter
from src.utils import normalize_url, print_banner, print_status

def main():
    parser = argparse.ArgumentParser(
        description="WebProbe - Web Application Vulnerability Scanner"
    )
    parser.add_argument("url", help="Target URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument("--output", default="report.html", help="Output HTML report filename")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    args = parser.parse_args()

    print_banner()

    target = normalize_url(args.url)
    print_status(f"Target: {target}", "info")
    print_status(f"Crawl depth: {args.depth}", "info")
    print()

    # ── Phase 1: Crawl ───────────────────────────────────────────────────────
    print_status("Phase 1/5 — Crawling target...", "phase")
    crawler = Crawler(target, max_depth=args.depth, timeout=args.timeout)
    pages, forms = crawler.crawl()
    print_status(f"Found {len(pages)} pages, {len(forms)} forms", "ok")
    print()

    all_findings = []

    # ── Phase 2: Header checks ───────────────────────────────────────────────
    print_status("Phase 2/5 — Checking security headers...", "phase")
    header_scanner = HeaderScanner(timeout=args.timeout)
    header_findings = header_scanner.scan(pages)
    all_findings.extend(header_findings)
    print_status(f"Found {len(header_findings)} header issue(s)", "ok")
    print()

    # ── Phase 3: XSS ────────────────────────────────────────────────────────
    print_status("Phase 3/5 — Testing for XSS...", "phase")
    xss_scanner = XSSScanner(timeout=args.timeout)
    xss_findings = xss_scanner.scan(forms)
    all_findings.extend(xss_findings)
    print_status(f"Found {len(xss_findings)} XSS issue(s)", "ok")
    print()

    # ── Phase 4: SQL Injection ───────────────────────────────────────────────
    print_status("Phase 4/5 — Testing for SQL injection...", "phase")
    sqli_scanner = SQLiScanner(timeout=args.timeout)
    sqli_findings = sqli_scanner.scan(forms, pages)
    all_findings.extend(sqli_findings)
    print_status(f"Found {len(sqli_findings)} SQLi issue(s)", "ok")
    print()

    # ── Phase 5: Open redirects ──────────────────────────────────────────────
    print_status("Phase 5/5 — Testing for open redirects...", "phase")
    redirect_scanner = RedirectScanner(timeout=args.timeout)
    redirect_findings = redirect_scanner.scan(pages)
    all_findings.extend(redirect_findings)
    print_status(f"Found {len(redirect_findings)} redirect issue(s)", "ok")
    print()

    # ── Report ───────────────────────────────────────────────────────────────
    reporter = Reporter(target, pages, forms, all_findings)
    reporter.save_html(args.output)
    reporter.print_summary()
    print()
    print_status(f"Report saved → {args.output}", "ok")

if __name__ == "__main__":
    main()
