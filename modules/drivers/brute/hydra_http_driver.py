import os
import subprocess
from tenacity import retry, stop_after_attempt, wait_fixed

from modules.core.driver import BaseToolDriver, DriverResult, ParsedResult

class HydraHttpDriver(BaseToolDriver):
    """
    Brute‐force HTTP form logins using hydra's http-form module.
    Expects kwargs:
      - form: { action, method, fields }  (from FormDiscovery)
      - userlist: path to usernames file
      - passlist: path to passwords file
    """
    name = "hydra_http"

    def __init__(self, config, session_mgr, logger):
        super().__init__(config, session_mgr, logger)
        self.binary    = config["hydra_binary"]
        self.output_dir= config["hydra_output_dir"]
        os.makedirs(self.output_dir, exist_ok=True)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, form: dict, userlist: str, passlist: str, **kwargs):
        # Normalize the form action URL
        action = form.get("action") or target
        if not action.startswith(("http://","https://")):
            action = f"http://{target.rstrip('/')}{action}"

        # Build the USER/PASS template
        fields = form.get("fields", {})
        tpl_parts = []
        for name, val in fields.items():
            nl = name.lower()
            if nl == self.config["hydra_http"]["username_field"]:
                tpl_parts.append(f"{name}=^USER^")
            elif nl == self.config["hydra_http"]["password_field"]:
                tpl_parts.append(f"{name}=^PASS^")
            else:
                tpl_parts.append(f"{name}={val}")
        form_tpl = "&".join(tpl_parts)

        # 1) Try to grab cookies from SessionManager
        session = self.session_mgr.get(target)
        ck = session.cookies.get_dict()
        if ck:
            cookie_header = ";".join(f"{k}={v}" for k, v in ck.items())
        else:
            # 2) Fallback to config override
            cookie_header = self.config["hydra_http"].get("cookie_header", "")

        # 3) Pick the failure string (allow override)
        fail_str = self.config["hydra_http"].get(
            "fail_string",
            self.config.get("http_fail_string", "invalid")
        )

        # 4) Build module argument
        module_arg = f"{action}:{form_tpl}:H=Cookie: {cookie_header}:F={fail_str}"

        # 5) Assemble & launch Hydra
        outfile = os.path.join(
            self.output_dir,
            f"{target.replace('://','_')}_hydra_http.txt"
        )
        cmd = [
            self.binary,
            "-L", userlist,
            "-P", passlist,
            "-f",            # stop on first valid
            "-o", outfile,
            target,
            "http-form-post",
            module_arg
        ]
        self.logger.info(f"[HydraHTTP] Running: {' '.join(cmd)}")
        subprocess.run(cmd, timeout=self.config["scan_timeout_sec"])
        return DriverResult(raw_output=outfile)

    def parse(self, raw_output_path: str) -> ParsedResult:
        """
        Parse hydra's output file lines like:
           [80][http-form-post] host:port login: admin   password: password123
        """
        creds = []
        with open(raw_output_path) as f:
            for line in f:
                if "login:" in line and "password:" in line:
                    parts = line.strip().split()
                    user = parts[parts.index("login:")+1]
                    pw   = parts[parts.index("password:")+1]
                    creds.append({"username": user, "password": pw})
        return ParsedResult(data={"credentials": creds})
