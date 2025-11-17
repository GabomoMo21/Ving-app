# pico_wifi_server.py — servidor puente TCP (PC)
import socket, threading, time

HOST = "0.0.0.0"
PORT = 12345

pico_conn = None
pico_lock = threading.Lock()

def _readline_from_pico(sock, timeout_ms=1500):
    """Lee UNA línea (\n) de la Pico con timeout. Devuelve str (sin \r\n) o cadena vacía."""
    sock.settimeout(0.05)
    buf = b""
    t0 = time.time()
    while (time.time() - t0) * 1000 < timeout_ms:
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            continue
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
        if buf.endswith(b"\n") or buf.endswith(b"\r"):
            break
    return buf.decode("utf-8", "ignore").strip()

def _translate_client_cmd(raw: str):
    """
    Normaliza y traduce lo que manda el cliente TCP a comandos que entiende la Pico.
    Devuelve (pico_cmd_str, respuesta_inmediata) donde:
      - pico_cmd_str: string para enviar a Pico con '\n' (o None si no hay que enviar a Pico)
      - respuesta_inmediata: bytes para responder al cliente sin hablar con Pico (o None)
    """
    s = raw.strip()
    if not s:
        return (None, b"")  # ignora vacío

    low = s.lower()
    parts = low.split()

    # quit: solo cerrar cliente
    if low == "quit":
        return (None, b"BYE\n")

    # ping: podemos responder local o preguntar a la Pico
    if low == "ping":
        # Opción A (local): return (None, b"PONG\n")
        # Opción B (hacia Pico): enviar PING a Pico
        return ("PING\n", None)

    # open / close
    if low == "open":
        return ("LOCK OPEN\n", None)
    if low == "close":
        return ("LOCK CLOSE\n", None)

    # servo <0..180>
    if len(parts) == 2 and parts[0] == "servo":
        try:
            ang = int(float(parts[1]))
        except Exception:
            return (None, b"ERR BAD ANGLE\n")
        ang = max(0, min(180, ang))
        return (f"SERVO {ang}\n", None)

    # cualquier otra cosa
    return (None, b"ERR UNKNOWN\n")

def handle_client(conn, addr):
    global pico_conn
    try:
        conn.sendall(b"Comandos: ping | open | close | servo <0..180> | quit\n")
        # Permite que el cliente mande varias líneas en un mismo paquete
        buffer = b""
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data
            # procesa por líneas
            lines = buffer.splitlines(keepends=False)
            # si el buffer no terminaba en \n, la última línea es incompleta: guárdala
            if not (buffer.endswith(b"\n") or buffer.endswith(b"\r")):
                buffer = lines.pop().encode("utf-8", "ignore") if lines else b""
            else:
                buffer = b""

            for line in lines:
                raw = line.decode("utf-8", "ignore").strip()
                pico_cmd, immediate = _translate_client_cmd(raw)

                if immediate is not None:
                    # respuesta local inmediata
                    conn.sendall(immediate)
                    if immediate == b"BYE\n":
                        return
                    continue

                # comandos que requieren Pico
                with pico_lock:
                    if pico_conn is None:
                        conn.sendall(b"ERR NO_PICO\n")
                        continue
                    try:
                        pico_conn.sendall(pico_cmd.encode("utf-8"))
                        resp = _readline_from_pico(pico_conn, timeout_ms=1500)
                        if resp:
                            conn.sendall((resp + "\n").encode("utf-8"))
                        else:
                            conn.sendall(b"ERR NO_RESP\n")
                    except Exception:
                        conn.sendall(b"ERR SEND\n")
    finally:
        try:
            conn.close()
        except Exception:
            pass

def accept_loop():
    global pico_conn
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"Servidor escuchando en {HOST}:{PORT}")
    while True:
        c, a = srv.accept()
        c.settimeout(10)
        try:
            first = c.recv(64)
        except Exception:
            try:
                c.close()
            except Exception:
                pass
            continue

        # ¿Es la Pico? manda PICO_READY al conectar
        if b"PICO_READY" in first:
            with pico_lock:
                # si ya había una Pico previa, cerrarla
                if pico_conn is not None:
                    try:
                        pico_conn.close()
                    except Exception:
                        pass
                pico_conn = c
            print("PICO conectado desde", a)
            # No hacemos hilo: este socket queda reservado para hablar con la Pico
        else:
            # Es un cliente (tu app)
            # Lo que leímos en 'first' puede contener comandos: reinyectarlo
            t = threading.Thread(target=_client_thread_with_prefeed, args=(c, a, first), daemon=True)
            t.start()

def _client_thread_with_prefeed(c, a, prefeed: bytes):
    # Empaqueta 'prefeed' para que el handler procese también lo que entró en el primer recv
    # (p. ej. si el cliente mandó 'open\n' justo al conectar)
    class PrefeedConn:
        def __init__(self, sock, pre):
            self.sock = sock
            self.buf = pre

        def recv(self, n):
            if self.buf:
                data = self.buf[:n]
                self.buf = self.buf[n:]
                return data
            return self.sock.recv(n)

        def sendall(self, b):
            return self.sock.sendall(b)

        def close(self):
            try:
                self.sock.close()
            except Exception:
                pass

    handle_client(PrefeedConn(c, prefeed), a)

if __name__ == "__main__":
    accept_loop()
