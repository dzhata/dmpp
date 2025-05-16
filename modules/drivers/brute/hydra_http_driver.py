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
        """
        Build Hydra http-form arguments:
          hydra -L userlist -P passlist target http-form-post 
             "/path:field1=^USER^&field2=^PASS^:[FAIL_STRING]" -f -o output
        """
        action = form["action"] or target
        method = form["method"].upper()
        fields = form["fields"].copy()

        # Hydra needs a “failure string” to detect bad logins.
        # Ideally you know something like "Login failed" or "Invalid credentials".
        fail_str = self.config.get("http_fail_string", "invalid")

        # Build the form template: field1=^USER^&field2=^PASS^&...
        tpl_pairs = []
        for k,v in fields.items():
            if k.lower() in (self.config.get("username_field","username"),):
                tpl_pairs.append(f"{k}=^USER^")
            elif k.lower() in (self.config.get("password_field","password"),):
                tpl_pairs.append(f"{k}=^PASS^")
            else:
                tpl_pairs.append(f"{k}={v}")
        form_tpl = "&".join(tpl_pairs)

        # Hydra module string
        module = f"http-form-{method.lower()}"
        module_arg = f"{action}:{form_tpl}:{fail_str}"

        outfile = os.path.join(self.output_dir, f"{target.replace('://','_')}_hydra_http.txt")
        cmd = [
            self.binary,
            "-L", userlist,
            "-P", passlist,
            "-f",                # exit on first success per user
            "-o", outfile,
            target, module, module_arg
        ]
        self.logger.info(f"[HydraHTTP] {cmd}")
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
