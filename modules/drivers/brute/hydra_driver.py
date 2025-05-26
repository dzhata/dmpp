import os
import re
import subprocess
import logging
from tenacity import retry, stop_after_attempt, wait_fixed

from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult
from modules.core.utils import safe_filename

class HydraDriver(BaseToolDriver):
    """
    Driver for Hydra brute-force attacks.
    Runs against network services (e.g., SSH, FTP) using username/password lists.
    Captures and parses successful logins.
    """
    name = "hydra"

    def __init__(self, config: dict, session_mgr, logger: logging.Logger):
        super().__init__(config, session_mgr, logger)
        # Path to hydra binary (default: "hydra")
        self.binary = config.get("hydra_binary", "hydra")
        # Additional arguments for hydra (from config or defaults)
        self.args = config.get("hydra_args", ["-L", "config/usernames.txt", "-P", "config/passwords.txt", "-f"])
        # Directory where hydra output files will be stored
        self.output_dir = config.get("hydra_output_dir", "results/raw/hydra")
        os.makedirs(self.output_dir, exist_ok=True)
        # Retry settings for robustness
        self._max_attempts = config.get("retry_attempts", 3)
        self._wait_sec = config.get("retry_wait_sec", 5)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, **kwargs) -> DriverResult:
        """
        Execute Hydra against the given target.
        If `services` is provided, brute-force each service (e.g. SSH/FTP).
        Otherwise, run hydra with defaults (may fail if not a supported service).
        Returns a list of output file paths.
        """
        services = kwargs.get("services", self.config.get("hydra_services", []))
        raw_outputs = []

        if not services:
            # Default: try the target as a host/IP with default hydra args
            output_file = os.path.join(self.output_dir, f"{safe_filename(target)}_hydra.txt")
            cmd = [self.binary, *self.args, "-o", output_file, target]
            self.logger.info(f"[HydraDriver] Running default: {' '.join(cmd)}", extra={"target": target})
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.config.get("scan_timeout_sec", 300))
            if proc.returncode not in (0, 255):
                err = proc.stderr.decode(errors="ignore")
                self.logger.error(f"[HydraDriver] Error: {err} | Command: {' '.join(cmd)}", extra={"target": target})
                raise RuntimeError("Hydra scan error")
            raw_outputs.append(output_file)
        else:
            # Run Hydra for each service: e.g., SSH/FTP modules
            for svc in services:
                module = svc.get("module")
                port = svc.get("port")
                # Always use safe_filename for flat, portable output file names
                file_name = f"{safe_filename(target)}_{module}_{port}_hydra.txt"
                output_file = os.path.join(self.output_dir, file_name)
                # Compose the Hydra target URI for service modules
                target_uri = f"{module}://{target}:{port}"
                cmd = [self.binary, *self.args, "-o", output_file, target_uri]
                self.logger.info(f"[HydraDriver] Running: {' '.join(cmd)}", extra={"target": target, "service": module})
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=self.config.get("scan_timeout_sec", 300))
                if proc.returncode not in (0, 255):
                    err = proc.stderr.decode(errors="ignore")
                    self.logger.error(f"[HydraDriver] Error: {err} | Command: {' '.join(cmd)}",
                                      extra={"target": target, "service": module})
                    continue
                raw_outputs.append(output_file)

        # Return DriverResult with all output file paths (even if empty)
        return DriverResult(raw_output=raw_outputs)

    def parse(self, raw_output_path) -> ParsedResult:
        """
        Parse all Hydra output files for credential pairs.
        Logs a warning if any output file is missing.
        Adds feedback if no credentials are found.
        Returns: {'credentials': [ {username, password, service_output}, ... ]}
        """
        # Accepts a single path or a list
        files = raw_output_path if isinstance(raw_output_path, list) else [raw_output_path]
        credentials = []

        for path in files:
            if not os.path.exists(path):
                self.logger.warning(f"[HydraDriver] Output file missing: {path}")
                continue
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    # Hydra output for a successful login typically looks like:
                    #   [22][ssh] host:22   login: admin   password: password123
                    m = re.search(r"login:\s*(\S+)\s*password:\s*(\S+)", line)
                    if m:
                        credentials.append({
                            "username": m.group(1),
                            "password": m.group(2),
                            "service_output": path
                        })
                    else:
                        # Fallback: old-school colon-separated format: host:port:login:password
                        parts = line.split(":")
                        if len(parts) >= 4:
                            credentials.append({
                                "username": parts[-2],
                                "password": parts[-1],
                                "service_output": path
                            })

        # User feedback: if no creds, log it
        if not credentials:
            self.logger.info(f"[HydraDriver] No valid credentials found for {files}")

        return ParsedResult(data={"credentials": credentials})
