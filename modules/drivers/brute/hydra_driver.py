import os
import re
import subprocess
import logging
from tenacity import retry, stop_after_attempt, wait_fixed

from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult


class HydraDriver(BaseToolDriver):
    """
    Driver for Hydra brute-force attacks. Runs against a target using configured username/password lists,
    captures credentials, and parses successful logins.
    """
    name = "hydra"

    def __init__(self, config: dict, session_mgr, logger: logging.Logger):
        super().__init__(config, session_mgr, logger)
        self.binary = config.get("hydra_binary", "hydra")
        self.args = config.get("hydra_args", ["-L", "config/usernames.txt", "-P", "config/passwords.txt", "-f"])
        self.output_dir = config.get("hydra_output_dir", "results/raw/hydra")
        os.makedirs(self.output_dir, exist_ok=True)

        # Retry settings (could be driven by config)
        self._max_attempts = config.get("retry_attempts", 3)
        self._wait_sec = config.get("retry_wait_sec", 5)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, **kwargs) -> DriverResult:
        """
        Execute Hydra against the target. Kwargs may include `services`, a list of dicts
        with keys: module, port (e.g. [{'module':'ssh','port':22}]).
        """
        services = kwargs.get("services", self.config.get("hydra_services", []))
        raw_outputs = []

        if not services:
            # Default brute against target without explicit module (Hydra will prompt error)
            output_file = os.path.join(self.output_dir, f"{target.replace(':', '_')}_hydra.txt")
            cmd = [self.binary, *self.args, "-o", output_file, target]
            self.logger.info(f"[HydraDriver] Running default: {' '.join(cmd)}", extra={"target": target})
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=self.config.get("scan_timeout_sec", 300))
            if proc.returncode not in (0, 255):
                err = proc.stderr.decode(errors="ignore")
                self.logger.error(f"[HydraDriver] Error: {err}", extra={"target": target})
                raise RuntimeError("Hydra scan error")
            raw_outputs.append(output_file)
        else:
            # Run per-service
            for svc in services:
                module = svc.get("module")
                port = svc.get("port")
                target_uri = f"{module}://{target}:{port}"
                file_name = f"{target.replace(':', '_')}_{module}_{port}_hydra.txt"
                output_file = os.path.join(self.output_dir, file_name)
                cmd = [self.binary, *self.args, "-o", output_file, target_uri]
                self.logger.info(f"[HydraDriver] Running: {' '.join(cmd)}", extra={"target": target, "service": module})
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=self.config.get("scan_timeout_sec", 300))
                if proc.returncode not in (0, 255):
                    err = proc.stderr.decode(errors="ignore")
                    self.logger.error(f"[HydraDriver] Error: {err}", extra={"target": target, "service": module})
                    continue
                raw_outputs.append(output_file)

        # If multiple outputs, return list; else single path
        return DriverResult(raw_output=raw_outputs)

    def parse(self, raw_output_path) -> ParsedResult:
        """
        Parse Hydra output files (string or list) and extract credential pairs.
        """
        files = raw_output_path if isinstance(raw_output_path, list) else [raw_output_path]
        credentials = []

        for path in files:
            if not os.path.exists(path):
                continue
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    # Match HTTP-form or SSH style: login: <user> password: <pass>
                    m = re.search(r"login:\s*(\S+)\s*password:\s*(\S+)", line)
                    if m:
                        credentials.append({
                            "username": m.group(1),
                            "password": m.group(2),
                            "service_output": path
                        })
                    else:
                        # Fallback: colon-separated format: host:port:login:password
                        parts = line.split(":")
                        if len(parts) >= 4:
                            credentials.append({
                                "username": parts[-2],
                                "password": parts[-1],
                                "service_output": path
                            })

        return ParsedResult(data={"credentials": credentials})
