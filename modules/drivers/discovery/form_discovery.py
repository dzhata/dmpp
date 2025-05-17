import requests
from bs4 import BeautifulSoup
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult

class FormDiscoveryDriver(BaseToolDriver):
    name = "form_discovery"

    def run(self, target: str, **kwargs) -> DriverResult:
        """
        GET the target URL (or login‐protected pages via session_mgr),
        save raw HTML to a temp file.
        """
        session = self.session_mgr.get(target)
        url     = target if target.startswith("http") else f"http://{target}"
        resp    = session.get(url, timeout=30)
        raw_path= f"results/raw/forms/{target.replace('://','_')}.html"
        with open(raw_path, "w") as f:
            f.write(resp.text)

        # Discover login forms at common paths
        paths = ["/", "/admin", "/test", "/dvwa"]
        forms = []
        for p in paths:
            candidate = f"http://{target}{p}/login.php"
            resp = requests.get(candidate, timeout=5)
            if resp.status_code == 200 and "DVWA – Login" in resp.text:
                forms.append({"url": candidate, "method": "POST"})
        # Optionally, save or log forms found here

        return DriverResult(raw_output=raw_path)

    def parse(self, raw_output_path: str) -> ParsedResult:
        """
        Use BeautifulSoup to extract:
         - form action URLs
         - method (GET/POST)
         - input names and default values
         - hidden CSRF tokens
        """
        soup = BeautifulSoup(open(raw_output_path), "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method","get").lower()
            fields = {}
            for inp in form.find_all("input"):
                name  = inp.get("name")
                value = inp.get("value","")
                fields[name] = value
            forms.append({
                "action": action,
                "method": method,
                "fields": fields
            })
        return ParsedResult(data={"forms": forms})
