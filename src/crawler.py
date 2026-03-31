"""
Crawler - discovers pages and forms on the target domain
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
from src.utils import print_status, safe_get


class Crawler:
    def __init__(self, base_url, max_depth=2, timeout=8):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.timeout = timeout
        self.visited = set()
        self.pages = []   # list of URLs visited
        self.forms = []   # list of form dicts

    def crawl(self):
        queue = deque([(self.base_url, 0)])

        while queue:
            url, depth = queue.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)

            resp = safe_get(url, self.timeout)
            if resp is None:
                continue

            self.pages.append(url)
            print_status(f"  Crawled: {url}", "crawl")

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract forms
            for form in soup.find_all("form"):
                form_data = self._parse_form(url, form)
                self.forms.append(form_data)

            # Extract links (stay on same domain)
            if depth < self.max_depth:
                for tag in soup.find_all("a", href=True):
                    link = urljoin(url, tag["href"])
                    parsed = urlparse(link)
                    if parsed.netloc == self.base_domain and link not in self.visited:
                        # Strip fragments
                        clean = parsed._replace(fragment="").geturl()
                        queue.append((clean, depth + 1))

        return self.pages, self.forms

    def _parse_form(self, page_url, form):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urljoin(page_url, action) if action else page_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_type = inp.get("type", "text").lower()
            inp_name = inp.get("name", "")
            inp_value = inp.get("value", "test")
            if inp_name:
                inputs.append({
                    "type": inp_type,
                    "name": inp_name,
                    "value": inp_value,
                })

        return {
            "page_url": page_url,
            "action_url": action_url,
            "method": method,
            "inputs": inputs,
        }
