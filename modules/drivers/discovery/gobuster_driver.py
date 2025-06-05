# modules/drivers/discovery/gobuster_driver.py

import os
import re
import subprocess
from urllib.parse import urlparse, urlunparse
import logging

from tenacity import retry, stop_after_attempt, wait_fixed
from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult
from modules.core.utils import safe_target_path  # helper to create consistent filenames


def run_gobuster_with_auto_exclude(target, output_file, base_cmd, logger, timeout_seconds=200):
    """
    Run Gobuster. If ambiguous 200s for non-existent URLs, extract length and retry with --exclude-length.
    """
    cmd = ["timeout", str(timeout_seconds)] + base_cmd
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    if proc.returncode in (0, 1):
        return proc

    err = proc.stderr.decode(errors="ignore")
    m = re.search(r"=>\s*\d+\s+\(Length:\s*(\d+)\)", err)
    if "matches the provided options for non existing urls" in err and m:
        length = m.group(1)
        logger.info(f"[GobusterDriver] Retrying with --exclude-length {length}")
        # Insert --exclude-length just before -o (output) argument
        retry_cmd = []
        inserted = False
        for idx, v in enumerate(base_cmd):
            if v == '-o' and not inserted:
                retry_cmd += ["--exclude-length", length]
                inserted = True
            retry_cmd.append(v)
        cmd_retry = ["timeout", str(timeout_seconds)] + retry_cmd
        proc2 = subprocess.run(cmd_retry, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc2

    logger.error(f"[GobusterDriver] Gobuster failed: {err}")
    raise RuntimeError(f"Gobuster failure: {err}")


class GobusterDriver(BaseToolDriver):
    name = "dirb"  # Legacy name for pipeline compatibility

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

    @retry(stop=stop_after_attempt(1), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, **kwargs) -> DriverResult:
        # Normalize URL
        raw = target if target.startswith(("http://", "https://")) else f"http://{target}"
        p = urlparse(raw)
        host = p.netloc
        path = p.path or "/"
        if not path.endswith("/"):
            path += "/"
        url = urlunparse((p.scheme, host, path, "", "", ""))

        # Output filename
        safe = safe_target_path(target, p.path)
        out_file = os.path.join(self.output_dir, f"{safe}.txt")
        os.makedirs(os.path.dirname(out_file), exist_ok=True)

        # Assemble Gobuster command
        # Do not allow self.args to include output/user/wordlist params
        cmd = [
            self.binary,
            *self.args,
            "-u", url,
            "-w", self.wordlist,
            "-o", out_file
        ]
        self.logger.info(f"[GobusterDriver] Running: {' '.join(cmd)}")
        try:
            proc = run_gobuster_with_auto_exclude(
                target, out_file, cmd, self.logger, timeout_seconds=600
            )
        except Exception as e:
            self.logger.error(f"[GobusterDriver] Gobuster exception: {e}")
            raise

        # Return code handling
        if proc.returncode == 1:
            # No hits: create empty output for consistent parsing
            try:
                open(out_file, 'w').close()
            except Exception as e:
                self.logger.error(f"[GobusterDriver] Failed to create empty output: {e}")
            return DriverResult(raw_output=out_file)

        if proc.returncode == 0:
            # Hits found: ensure file exists
            if not os.path.exists(out_file):
                self.logger.warning(
                    f"[GobusterDriver] Expected output file missing despite hits, creating empty: {out_file}"
                )
                open(out_file, 'w').close()
            return DriverResult(raw_output=out_file)

        # Other codes should have been handled
        err = proc.stderr.decode(errors="ignore")
        self.logger.error(f"[GobusterDriver] Scan failed (code {proc.returncode}): {err}")
        raise RuntimeError(f"Gobuster scan failed (code {proc.returncode})")

    def parse(self, raw_output_path: str) -> ParsedResult:
        # Return empty if file missing
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
            f"[GobusterDriver] Parsed {len(paths)} paths from {raw_output_path}"
        )
        return ParsedResult(data={"paths": paths})
