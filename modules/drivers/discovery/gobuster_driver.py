# modules/drivers/discovery/gobuster_driver.py

import os
import re
import subprocess
from urllib.parse import urlparse, urlunparse
import logging

from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult
from modules.core.utils import safe_target_path  # helper to create consistent filenames


def run_gobuster_with_auto_exclude(target, output_file, base_cmd, logger):
    """
    Run Gobuster, and if it fails due to ambiguous 200 status for non-existent URLs,
    extract the suggested length and retry with --exclude-length.
    """
    proc = subprocess.run(base_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # 0: hits found, 1: no hits
    if proc.returncode in (0, 1):
        return proc

    err = proc.stderr.decode(errors="ignore")
    m = re.search(r"=>\s*\d+\s+\(Length:\s*(\d+)\)", err)
    if "matches the provided options for non existing urls" in err and m:
        length = m.group(1)
        logger.info(f"[GobusterDriver] Retrying with --exclude-length {length}")
        retry_cmd = []
        inserted = False
        for v in base_cmd:
            if v == '-o' and not inserted:
                retry_cmd += ["--exclude-length", length]
                inserted = True
            retry_cmd.append(v)
        proc2 = subprocess.run(retry_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc2

    logger.error(f"[GobusterDriver] Gobuster failed: {err}")
    raise RuntimeError(f"Gobuster failure: {err}")


class GobusterDriver(BaseToolDriver):
    name = "dirb"  # Stage name “dirb” kept for pipeline compatibility

    def __init__(self, config: dict, session_mgr, logger: logging.Logger):
        super().__init__(config, session_mgr, logger)
        self.binary = config.get("gobuster_binary", "gobuster")
        self.wordlist = config.get(
            "dirb_wordlist",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        )
        self.args = config.get(
            "gobuster_args",
            ["dir", "-r", "-t", "50", "-b", "404,403", "-q"]
        )
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
        # Build normalized URL
        raw = target if target.startswith(("http://", "https://")) else f"http://{target}"
        p = urlparse(raw)
        host = p.netloc
        path = p.path or "/"
        if not path.endswith("/"):
            path += "/"
        url = urlunparse((p.scheme, host, path, "", "", ""))

        # Determine safe output filename
        safe = safe_target_path(target, p.path)
        out_file = os.path.join(self.output_dir, f"{safe}.txt")
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        # Execute Gobuster with auto-exclusion logic
        cmd = [
            self.binary,
            *self.args,
            "-u", url,
            "-w", self.wordlist,
            "-o", out_file
        ]
        self.logger.info(f"[GobusterDriver] Running: {' '.join(cmd)}", extra={"target": target})
        proc = run_gobuster_with_auto_exclude(target, out_file, cmd, self.logger)

        # Handle return codes
        if proc.returncode == 1:
            # No hits: create empty output file for consistent parsing
            try:
                open(out_file, 'w').close()
            except Exception as e:
                self.logger.error(f"[GobusterDriver] Failed to create empty output: {e}", extra={"target": target})
            return DriverResult(raw_output=out_file)

        if proc.returncode == 0:
            # Hits found: ensure file exists
            if not os.path.exists(out_file):
                self.logger.warning(
                    f"[GobusterDriver] Expected output file missing despite hits, creating empty: {out_file}",
                    extra={"target": target}
                )
                open(out_file, 'w').close()
            return DriverResult(raw_output=out_file)

        # Other codes should have been caught in auto-exclude logic
        err = proc.stderr.decode(errors="ignore")
        self.logger.error(f"[GobusterDriver] Scan failed (code {proc.returncode}): {err}", extra={"target": target})
        raise RuntimeError(f"Gobuster scan failed (code {proc.returncode})")

    def parse(self, raw_output_path: str) -> ParsedResult:
        # If for some reason the file is still missing, return empty paths
        if not os.path.exists(raw_output_path):
            self.logger.warning(f"[GobusterDriver] Missing file at parse: {raw_output_path}")
            return ParsedResult(data={"paths": []})

        paths = []
        with open(raw_output_path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("/"):
                    parts = line.split()
                    paths.append(parts[0])
        self.logger.debug(
            f"[GobusterDriver] Parsed {len(paths)} paths from {raw_output_path}",
            extra={"raw": raw_output_path}
        )
        return ParsedResult(data={"paths": paths})
