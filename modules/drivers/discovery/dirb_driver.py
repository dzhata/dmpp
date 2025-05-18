# modules/drivers/discovery/dirb_driver.py

import os
import subprocess
import logging

from urllib.parse import urlparse, urlunparse
from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult

class DirbDriver(BaseToolDriver):
    """
    Driver for directory enumeration (e.g. Gobuster/Dirb).
    Discovers paths under a web root by brute-forcing against a wordlist.
    """
    name = "dirb"

    def __init__(self, config: dict, session_mgr, logger: logging.Logger):
        super().__init__(config, session_mgr, logger)
        # Tool binary (default to gobuster)
        self.binary     = config.get("dirb_binary", "gobuster")
        # Default wordlist for web-content discovery
        self.wordlist   = config.get(
            "dirb_wordlist",
            "/usr/share/wordlists/dirb/common.txt"
        )
        # Any extra args (e.g. ["dir", "-q"] for quiet mode)
        self.args       = config.get("dirb_args", ["dir", "-q"])
        # Where to save raw output
        self.output_dir = config.get("dirb_output_dir", "results/raw/dirb")
        os.makedirs(self.output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, **kwargs) -> DriverResult:
        """
        Run directory busting against the target root URL.

        :param target: e.g. "10.0.0.5" or "http://10.0.0.5"
        :return: DriverResult with path to the raw output file
        """
        raw = target if target.startswith(("http://","https://")) else f"http://{target}"
        p   = urlparse(raw)

        host = p.netloc
        # keep case of p.path (e.g. "/DVWA"), enforce trailing slash
        path = p.path or "/"
        if not path.endswith("/"):
            path += "/"
        # Ensure we have a full URL
        url = urlunparse((p.scheme, host, path, "", "", ""))
        # Filename-safe target identifier
        safe = f"{host}{path}".replace("/", "_").strip("_")
        out_file = os.path.join(self.output_dir, f"{safe}.txt")
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        cmd = [
            self.binary,
            *self.args,
            "-u", url,
            "-w", self.wordlist,
            "-o", out_file
        ]
        self.logger.info(f"[DirbDriver] Running: {' '.join(cmd)}", extra={"target": target})
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.config.get("scan_timeout_sec", 300)
        )

        # Gobuster/Dirb returncode 0 = hits found, 1 = no hits, others = error
        if proc.returncode not in (0, 1):
            err = proc.stderr.decode(errors="ignore")
            self.logger.error(f"[DirbDriver] Error: {err}", extra={"target": target})
            raise RuntimeError(f"Dirb scan error (code {proc.returncode})")

        self.logger.debug(f"[DirbDriver] Output saved to {out_file}", extra={"target": target})
        return DriverResult(raw_output=out_file)

    def parse(self, raw_output_path: str) -> ParsedResult:
        """
        Read the raw output lines and extract discovered paths.

        Returns:
            ParsedResult.data = {"paths": ["/dvwa", "/admin", ...]}
        """
        paths = []
        with open(raw_output_path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                # Gobuster/Dirb list hits as e.g. "/dvwa (Status: 301)"
                if line.startswith("/"):
                    parts = line.split()
                    paths.append(parts[0])
        self.logger.debug(f"[DirbDriver] Parsed {len(paths)} paths", extra={"raw": raw_output_path})
        return ParsedResult(data={"paths": paths})
