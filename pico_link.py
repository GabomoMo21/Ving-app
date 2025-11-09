# pico_link.py — Enlace USB con Raspberry Pi Pico W (MicroPython)
import time
import serial
from serial.tools import list_ports

DEFAULT_BAUD = 115200
READ_TIMEOUT = 0.8

class PicoLink:
    def __init__(self, port: str | None = None, baud: int = DEFAULT_BAUD):
        self.port = port
        self.baud = baud
        self.ser: serial.Serial | None = None

    # ---- Detección más permisiva para Windows ----
    def _auto_detect_port(self) -> str | None:
        """
        Intenta hallar el puerto del Pico por distintos indicios:
        - VID:PID=2E8A:* (RP2040)
        - Palabras clave en descripción/hwid: pico, rp2040, micropython
        - Fallback: si hay un solo puerto serie, úsalo
        """
        ports = list(list_ports.comports())
        if not ports:
            return None

        # 1) Coincidencia por VID/PID del RP2040
        for p in ports:
            hwid = (p.hwid or "").upper()
            if "VID:PID=2E8A:" in hwid:           # RP2040 (Raspberry Pi)
                return p.device

        # 2) Palabras clave en descripción/fabricante/hwid
        for p in ports:
            desc = f"{p.description} {p.manufacturer} {p.hwid}".lower()
            if any(k in desc for k in ("pico", "rp2040", "micropython")):
                return p.device

        # 3) Windows suele mostrarlo como "USB Serial Device"
        for p in ports:
            desc = f"{p.description} {p.hwid}".lower()
            if "usb serial device" in desc and "2e8a" in desc:
                return p.device

        # 4) Fallback: si solo hay un puerto serie, usa ese
        if len(ports) == 1:
            return ports[0].device

        return None

    def open(self):
        if not self.port:
            self.port = self._auto_detect_port()

        if not self.port:
            # Mensaje con ayuda y puertos disponibles
            available = ", ".join(f"{p.device} [{p.description} | {p.hwid}]"
                                  for p in list_ports.comports())
            raise RuntimeError(
                "No se encontró el puerto del Pico. Conéctalo por USB o indica el puerto manualmente.\n"
                f"Puertos vistos por el sistema: {available or '(ninguno)'}\n"
                "También puedes pasar el puerto explícito: PicoLink(port='COM5').open()"
            )

        # Abre el puerto
        self.ser = serial.Serial(self.port, self.baud, timeout=READ_TIMEOUT)
        self.ser.dtr = False
        self.ser.rts = False
        self.ser.reset_input_buffer()
        time.sleep(0.25)  # pequeña espera

        # Handshake robusto: acepta PICO_READY de arranque o responde a PING
        # 1) lee ráfagas por si justo alcanzamos a ver el PICO_READY
        boot = self._readline()
        if boot and "PICO_READY" in boot:
            return self

        # 2) envía PING y espera PONG
        self._writeln("PING")
        pong = self._readline()
        if pong and "PONG" in pong:
            return self

        # 3) como último intento, pide un NO-OP (SERVO 90?) y revisa eco
        self._writeln("SERVO 90")
        resp = self._readline()
        if resp and ("OK SERVO" in resp or "ERR" in resp):
            return self

        self.close()
        raise RuntimeError("No hubo respuesta del Pico (handshake fallido). "
                           "Revisa que Thonny no tenga el puerto abierto y el cable sea de datos.")

    def close(self):
        try:
            if self.ser:
                self.ser.close()
        finally:
            self.ser = None

    # ------------ Comandos de alto nivel ------------
    def lock_open(self) -> bool:
        return self._cmd_ok("LOCK OPEN", ok_contains="OK LOCK OPEN")

    def lock_close(self) -> bool:
        return self._cmd_ok("LOCK CLOSE", ok_contains="OK LOCK CLOSE")

    def set_angle(self, deg: int) -> bool:
        return self._cmd_ok(f"SERVO {deg}", ok_contains="OK SERVO")

    # --------------- utilidades ---------------------
    def _writeln(self, s: str):
        if not self.ser:
            raise RuntimeError("Puerto no abierto")
        self.ser.write((s + "\n").encode("utf-8"))

    def _readline(self) -> str | None:
        if not self.ser:
            return None
        try:
            line = self.ser.readline()
            if not line:
                return None
            return line.decode(errors="ignore").strip()
        except Exception:
            return None

    def _cmd_ok(self, s: str, ok_contains: str) -> bool:
        try:
            self._writeln(s)
            t0 = time.time()
            while time.time() - t0 < 1.5:
                r = self._readline()
                if not r:
                    continue
                if ok_contains in r:
                    return True
                if r.startswith("ERR"):
                    return False
            return False
        except Exception:
            return False
