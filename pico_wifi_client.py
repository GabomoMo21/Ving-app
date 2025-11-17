# pico_wifi_client.py
import socket

class PicoWifi:
    def __init__(self, host="127.0.0.1", port=12345, timeout=2.0):
        self.host = host
        self.port = port
        self.timeout = float(timeout)

    def _send_cmd(self, cmd: str) -> str:
        data = (cmd.strip() + "\n").encode("utf-8", "ignore")
        with socket.create_connection((self.host, self.port), self.timeout) as s:
            s.settimeout(self.timeout)
            s.sendall(data)
            chunks = []
            while True:
                try:
                    b = s.recv(4096)
                except socket.timeout:
                    break
                if not b:
                    break
                chunks.append(b)
            return (b"".join(chunks)).decode("utf-8", "ignore").strip()

    # Comandos de alto nivel (cliente → servidor)
    def ping(self) -> str:
        # El servidor espera 'ping'
        return self._send_cmd("ping")

    def lock_open(self) -> str:
        # El servidor traduce 'open' → 'LOCK OPEN' hacia la Pico
        return self._send_cmd("open")

    def lock_close(self) -> str:
        # El servidor traduce 'close' → 'LOCK CLOSE' hacia la Pico
        return self._send_cmd("close")

    def servo(self, angle: int) -> str:
        # El servidor traduce 'servo <n>' → 'SERVO n' hacia la Pico
        angle = max(0, min(180, int(angle)))
        return self._send_cmd(f"servo {angle}")
