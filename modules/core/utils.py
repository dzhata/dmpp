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
    return target.replace('://', '_').replace(':', '_').replace('/', '_')

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
