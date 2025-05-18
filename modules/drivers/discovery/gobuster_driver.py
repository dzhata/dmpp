# modules/drivers/discovery/gobuster_driver.py

import os
import subprocess
from urllib.parse import urlparse, urlunparse
import logging

from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult

class GobusterDriver(BaseToolDriver):
    name = "dirb"     # keep stage name “dirb” so pipeline needs no renaming

    def __init__(self, config: dict, session_mgr, logger: logging.Logger):
        super().__init__(config, session_mgr, logger)
        # Point at the Gobuster binary
        self.binary   = config.get("gobuster_binary", "gobuster")
        # Large SecLists by default
        self.wordlist = config.get(
            "dirb_wordlist",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        )
        # Gobuster flags: threads, status codes to show, extensions, quiet
        self.args     = config.get(
            "gobuster_args",
            ["dir", "-r","--recursion-depth","3", "-t", "50", "-b", "404,403", "-x", "php,html", "-q"]
        )
        # Base results folder
        project_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../..")
        )
        self.output_dir = os.path.join(
            project_root,
            config.get("dirb_output_dir", "results/raw/dirb")
        )
        os.makedirs(self.output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, **kwargs) -> DriverResult:
        # 1) Normalize & parse URL
        raw = target if target.startswith(("http://","https://")) else f"http://{target}"
        p   = urlparse(raw)
        host = p.netloc
        path = p.path or "/"
        if not path.endswith("/"):
            path += "/"
        url  = urlunparse((p.scheme, host, path, "", "", ""))

        # 2) Prepare safe filename & ensure its directory exists
        safe     = f"{host}{path}".replace("/", "_").strip("_")
        out_file = os.path.join(self.output_dir, f"{safe}.txt")
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        # 3) Build and fire Gobuster
        cmd = [
            self.binary,
            *self.args,
            "-u", url,
            "-w", self.wordlist,
            "-o", out_file
        ]
        self.logger.info(f"[GobusterDriver] Running: {' '.join(cmd)}", extra={"target": target})
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.config.get("scan_timeout_sec", 300),
        )
        if proc.returncode not in (0, 1):
            err = proc.stderr.decode(errors="ignore")
            self.logger.error(f"[GobusterDriver] Error: {err}", extra={"target": target})
            raise RuntimeError(f"Gobuster scan failed (code {proc.returncode})")

        self.logger.debug(f"[GobusterDriver] Output → {out_file}", extra={"target": target})
        return DriverResult(raw_output=out_file)

    def parse(self, raw_output_path: str) -> ParsedResult:
        paths = []
        with open(raw_output_path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                # Gobuster hits look like "/dvwa (Status: 301)"
                if line.startswith("/"):
                    parts = line.split()
                    paths.append(parts[0])
        self.logger.debug(f"[GobusterDriver] Parsed {len(paths)} paths", extra={"raw": raw_output_path})
        return ParsedResult(data={"paths": paths})
