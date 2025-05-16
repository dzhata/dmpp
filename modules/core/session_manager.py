import threading
import requests


class SessionManager:
    """
    Manages HTTP sessions (cookies, headers) per target, ensuring reuse across drivers.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions = {}

    def get(self, target: str) -> requests.Session:
        """
        Retrieve or create a requests.Session for a given target.
        """
        with self._lock:
            if target not in self._sessions:
                session = requests.Session()
                # You can customize default headers or proxies here,
                # e.g. session.headers.update({'User-Agent': 'PentestFramework/1.0'})
                self._sessions[target] = session
            return self._sessions[target]

    def clear(self, target: str = None) -> None:
        """
        Clear session(s). If target is specified, clears only that session;
        otherwise clears all sessions.
        """
        with self._lock:
            if target:
                self._sessions.pop(target, None)
            else:
                self._sessions.clear()
