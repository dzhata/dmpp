# modules/drivers/vuln/sqlmap_driver.py

import os
import subprocess
from urllib.parse import urlparse, urljoin
from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult

class SQLMapDriver(BaseToolDriver):
    """
    Driver to run SQLMap against each discovered form,
    saving output and scanning for SQL injection findings.
    """
    name = "sqlmap"

    def __init__(self, config: dict, session_mgr, logger):
        super().__init__(config, session_mgr, logger)

        # Path to sqlmap binary (usually just "sqlmap" on Kali)
        self.binary = config.get("sqlmap_binary", "sqlmap")
        
        # Only use arguments from config—do not append anything here!
        # E.g., ["--batch", "--level", "5", "--risk", "3", "--crawl", "2", "--technique", "BEUSTQ", "-v", "2"]
        self.args = config.get(
            "sqlmap_args",
            ["--batch", "--level", "5", "--risk", "3", "--crawl", "2"]
        )

        # Output directory for raw SQLMap scan results
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        self.outdir = os.path.join(
            project_root,
            config.get("sqlmap_output_dir", "results/raw/sqlmap")
        )
        os.makedirs(self.outdir, exist_ok=True)

        # Location where AuthDriver may have saved session cookies
        self.cookie_dir = config.get("cookie_output_dir", "results/raw/cookies")

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, forms: list, **kwargs) -> DriverResult:
        """
        For each form discovered on the target, run SQLMap.
        Save the raw stdout to results/raw/sqlmap/<host>/form_<idx>.txt.
        Returns a DriverResult listing all output files created.
        """
        raw_outputs = []

        # Parse the target to extract the hostname
        url_parsed = urlparse(target if target.startswith(("http://", "https://")) else f"http://{target}")
        host = url_parsed.netloc.replace(":", "_")  # e.g., "127.0.0.1"
        host_dir = os.path.join(self.outdir, host)
        os.makedirs(host_dir, exist_ok=True)

        # Check for a cookie file and add --cookie-file if it exists
        cookie_file = os.path.join(self.cookie_dir, f"{host}.txt")
        cookie_arg = ["--cookie-file", cookie_file] if os.path.exists(cookie_file) else []

        for idx, form in enumerate(forms):
            fields = form.get("fields", {})
            # Skip forms that have <=1 field (likely not injectable)
            if len(fields) <= 1:
                self.logger.debug(f"[SQLMapDriver] Skipping form #{idx}: too few fields", extra={"target": target})
                continue

            # Build the absolute URL for the form's action
            action = form.get("action") or target
            if not action.startswith(("http://", "https://")):
                # Instead of joining with the host, join with the URL of the form itself!
                action = urljoin(target if target.startswith(("http://", "https://")) else f"http://{target}", action)


            # Assemble the POST data string (e.g., "user=1&pass=2")
            post_data = "&".join(f"{k}={v}" for k, v in fields.items())

            # Prepare the path to save SQLMap's output for this form
            out_path = os.path.join(host_dir, f"form_{idx}.txt")

            # Build the full command line for SQLMap
            cmd = [
                self.binary,
                "-u", action,
                "--data", post_data,
                *cookie_arg,
                *self.args
            ]

            self.logger.info(f"[SQLMapDriver] Running: {' '.join(cmd)}", extra={"target": target, "form": idx})
            # Execute SQLMap as a subprocess, capturing output and errors
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.config.get("scan_timeout_sec", 300)
                )
            except subprocess.TimeoutExpired as e:
                self.logger.error(f"SQLMap timeout on {action_url}: {e}")
                # Do not re-queue! Just continue
                continue


            # Only accept standard SQLMap return codes (0 = no SQLi, 1 = SQLi found)
            if proc.returncode not in (0, 1):
                err = proc.stderr.decode(errors="ignore")
                self.logger.error(f"[SQLMapDriver] Error on form #{idx}: {err}", extra={"target": target})
                continue

            # Write raw SQLMap stdout to a .txt file for this form
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(proc.stdout.decode(errors="ignore"))
            raw_outputs.append(out_path)
            self.logger.debug(f"[SQLMapDriver] Saved output to {out_path}", extra={"target": target})

        return DriverResult(raw_output=raw_outputs)

    def parse(self, raw_output_paths) -> ParsedResult:
        """
        Scan SQLMap output files for simple SQL injection indicators.
        Returns a list of findings per output.
        """
        findings = []
        for jpath in raw_output_paths or []:
            try:
                with open(jpath, "r", encoding="utf-8") as f:
                    text = f.read()
                # Heuristic: look for keywords in the output
                # You can expand this for more specific patterns
                if "is vulnerable" in text.lower() or "sql injection" in text.lower():
                    findings.append({"file": jpath, "evidence": "SQLi found"})
            except Exception as e:
                self.logger.error(f"[SQLMapDriver] Failed to parse {jpath}: {e}")
                continue

        return ParsedResult(data={"injections": findings})
