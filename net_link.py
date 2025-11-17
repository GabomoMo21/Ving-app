# net_link.py — cliente HTTP simple para hablar con la Pico W
import urllib.request
import urllib.error
import json

class NetworkPicoLink:
    def __init__(self, base_url: str, token: str):
        # base_url ej.: "http://192.168.1.120:8080"
        self.base = base_url.rstrip("/")
        self.token = token

    def _req(self, method: str, path: str):
        url = self.base + path
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                return r.read().decode("utf-8", "ignore").strip()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}")
        except Exception as e:
            raise RuntimeError(str(e))

    def ping(self) -> bool:
        return self._req("GET", "/ping") == "PONG"

    def lock_open(self) -> bool:
        return "OK" in self._req("POST", "/lock/open")

    def lock_close(self) -> bool:
        return "OK" in self._req("POST", "/lock/close")

    def status(self) -> str:
        return self._req("GET", "/status")
