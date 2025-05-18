# modules/drivers/discovery/form_discovery_driver.py

import os
import logging
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult

class FormDiscoveryDriver(BaseToolDriver):
    """
    Crawl a list of URLs, save raw HTML, and extract every form.
    Works on root targets or on nested paths from Gobuster.
    """
    name = "form_discovery"

    def __init__(self, config: dict, session_mgr, logger: logging.Logger):
        super().__init__(config, session_mgr, logger)

        # Build an absolute output directory under project root
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../..")
        )
        self.output_dir = os.path.join(
            project_root,
            config.get("form_output_dir", "results/raw/forms")
        )
        os.makedirs(self.output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, **kwargs) -> DriverResult:
        """
        GET the exact URL (target may be http://host/, http://host/path/, or http://host/path/page.php),
        save the raw HTML to results/raw/forms/<safe_target>.html.
        """
        # 1) Normalize URL
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        session = self.session_mgr.get(target)  # shared session (cookies, auth) :contentReference[oaicite:2]{index=2}:contentReference[oaicite:3]{index=3}

        # 2) Fetch
        self.logger.info(f"[FormDiscoveryDriver] Fetching {url}", extra={"target": target})
        resp = session.get(url, timeout=self.config.get("http_timeout", 30))
        resp.raise_for_status()

        # 3) Save raw HTML
        #    filename: replace :// and / with _
        safe = url.replace("://", "_").replace("/", "_").strip("_")
        raw_path = os.path.join(self.output_dir, f"{safe}.html")
        os.makedirs(os.path.dirname(raw_path), exist_ok=True)

        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(resp.text)
        self.logger.debug(f"[FormDiscoveryDriver] Saved HTML to {raw_path}", extra={"target": target})

        return DriverResult(raw_output=raw_path)

    def parse(self, raw_output_path: str) -> ParsedResult:
        """
        Parse the saved HTML and extract all <form> elements:
          - action URL
          - method (get/post)
          - input names & default values (including hidden CSRF tokens)
        """
        with open(raw_output_path, "r", encoding="utf-8") as f:
            soup = BeautifulSoup(f, "html.parser")

        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            method = form.get("method", "get").strip().lower()
            fields = {}

            for inp in form.find_all("input"):
                name = inp.get("name")
                if not name:
                    continue
                fields[name] = inp.get("value", "")

            forms.append({
                "action": action,
                "method": method,
                "fields": fields
            })

        self.logger.debug(
            f"[FormDiscoveryDriver] Parsed {len(forms)} forms from {raw_output_path}",
            extra={"raw": raw_output_path}
        )
        return ParsedResult(data={"forms": forms})
