from pymetasploit3.msfrpc import MsfRpcClient

def get_ip(target):
    import re
    m = re.match(r'(?:https?://)?([\d\.]+)', target)
    return m.group(1) if m else target

def update_metasploit_sessions(config, logger=None):
    msfrpc_pass = config.get("msfrpc_password", "workplease")
    msfrpc_host = config.get("msfrpc_host", "127.0.0.1")
    msfrpc_port = config.get("msfrpc_port", 55553)
    client = MsfRpcClient(msfrpc_pass, server=msfrpc_host, port=msfrpc_port)

    session_map = {}
    for sid, session in client.sessions.list.items():
        # Extract target IP or hostname from session info (host, etc)
        target = session.get("target_host") or session.get("session_host") or session.get("tunnel_peer")
        if target:
            # Remove port from tunnel_peer if present
            if ":" in target:
                target = target.split(":")[0]
            session_map.setdefault(target, []).append(sid)
    config["metasploit_sessions"] = session_map
    if logger:
        logger.info(f"[Pipeline] Updated Meterpreter sessions: {session_map}")

def should_skip_sqlmap_form(action_url: str, form: dict) -> bool:
        """
        Returns True if a form should NOT be scanned by SQLMap.
        Update logic as needed.
        """
        # Skip setup or installer forms by URL
        if any(x in action_url for x in ("setup.php", "install.php", "reset.php")):
            return True
        # Skip forms with no action or that point to "#" or are obviously non-injectable
        if not action_url or action_url.strip() in ("#", "/#", ""):
            return True
        # Skip forms with <=1 field (already handled in driver, but here for safety)
        fields = form.get("fields", {})
        if len(fields) <= 1:
            return True
        # Skip logout forms or known non-app logic
        if any(x in action_url for x in ("logout", "signout")):
            return True
        # You can add more custom logic here
        return False

def safe_filename(target: str) -> str:
    return target.replace('://', '_').replace(':', '_').replace('/', '_').replace('.', '_')

def is_plain_host(target):
            # Accepts only hostnames or IPs, not URLs or paths
            import re
            # Must NOT contain '/', must be just word/number/dot/hyphen
            return re.match(r'^[a-zA-Z0-9.\-]+$', target) is not None

def safe_target_path(target: str, path: str = "") -> str:
    """
    Returns a safe filename for any target + optional subpath
    e.g. target: 'http://127.0.0.1:3000', path: '/DVWA/'
         -> 'http_127.0.0.1_3000_DVWA'
    """
    from urllib.parse import urlparse
    p = urlparse(target if "://" in target else f"http://{target}")
    host = p.hostname or p.netloc
    port = f"_{p.port}" if p.port else ""
    scheme = p.scheme if p.scheme else "http"
    base = f"{scheme}_{host}{port}"
    # Path can be blank, or like '/DVWA/'
    if path:
        base += "_" + path.replace("/", "_").strip("_")
    return base.strip("_")
