# modules/drivers/discovery/dirb_driver.py

import os
import subprocess
from urllib.parse import urlparse, urlunparse
from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult
from modules.core.utils import safe_filename
class DirbDriver(BaseToolDriver):
    name = "dirb"

    def __init__(self, config: dict, session_mgr, logger):
        super().__init__(config, session_mgr, logger)

        # 1) Prefer explicit setting, else use the classic dirb tool
        self.binary     = config.get("dirb_binary", "dirb")
        # 2) Default args for dirb (not gobuster).  Remove any "dir" subcommand.
        self.args       = config.get(
            "dirb_args",
            ["-s", "200,301,302", "-x", "php,html"]
        )
        self.wordlist   = config.get(
            "dirb_wordlist",
            "/usr/share/wordlists/dirb/common.txt"
        )
        self.output_dir = config.get("dirb_output_dir", "results/raw/dirb")
        os.makedirs(self.output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, **kwargs) -> DriverResult:
        # Normalize to full URL
        raw = target if target.startswith(("http://","https://")) else f"http://{target}"
        p   = urlparse(raw)
        host = p.netloc
        path = p.path or "/"
        if not path.endswith("/"):
            path += "/"
        url = urlunparse((p.scheme, host, path, "", "", ""))

        # Build a filename‐safe identifier
        safe = f"{host}{path}".replace("/", "_").strip("_")
        out_file = os.path.join(self.output_dir, f"{safe}.txt")
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        # Assemble dirb command
        cmd = [
            self.binary,
            *self.args,
            url,
            self.wordlist,
            "-o", out_file
        ]
        self.logger.info(f"[DirbDriver] Running: {' '.join(cmd)}", extra={"target": target})
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.config.get("scan_timeout_sec", 300)
        )
        if proc.returncode not in (0, 1):
            err = proc.stderr.decode(errors="ignore")
            raise RuntimeError(f"[DirbDriver] scan error (code {proc.returncode}): {err}")

        return DriverResult(raw_output=out_file)

    def parse(self, raw_output_path: str) -> ParsedResult:
        # If gobuster/dirb never wrote a file, just return no paths
        if not os.path.exists(raw_output_path):
            self.logger.warning(f"[DirbDriver] No output file at {raw_output_path}; skipping parse")
            return ParsedResult(data={"paths": []})

        paths = []
        with open(raw_output_path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("/"):
                    parts = line.split()
                    paths.append(parts[0])
        self.logger.debug(f"[DirbDriver] Parsed {len(paths)} paths", extra={"raw": raw_output_path})
        return ParsedResult(data={"paths": paths})
