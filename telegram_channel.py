# telegram_channel.py
import requests
from datetime import datetime


class TelegramNotificationChannel:
    """
    Encapsula el envío de mensajes al bot de Telegram.
    Se usa desde la app para mandar textos o eventos formateados.
    """

    def __init__(self, bot_token: str):
        self.bot_token = bot_token
        self.api_url = f"https://api.telegram.org/bot{bot_token}"

    def enviar_texto(self, chat_id: int, texto: str):
        """
        Envía un mensaje de texto simple a un chat.
        """
        if not self.bot_token:
            print("TelegramNotificationChannel: bot_token vacío, no se envía nada.")
            return

        try:
            requests.get(
                self.api_url + "/sendMessage",
                params={"chat_id": chat_id, "text": texto},
                timeout=5,
            )
        except Exception as e:
            print("Error enviando mensaje a Telegram:", e)

    def enviar_evento(
        self,
        chat_id: int,
        dispositivo: str,
        severidad: str,
        titulo: str,
        cuerpo: str,
    ):
        """
        Envía un mensaje formateado a partir de un evento.
        severidad: 'low', 'medium', 'high', 'critical'
        """
        s = (severidad or "").lower()
        icono = "ℹ️"
        etiqueta = "INFO"

        if s == "critical":
            icono, etiqueta = "🚨", "CRÍTICO"
        elif s in ("high", "medium"):
            icono, etiqueta = "⚠️", "ALTO"

        ahora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        mensaje = (
            f"{icono} [{etiqueta}] {dispositivo}\n"
            f"{titulo}: {cuerpo}\n"
            f"{ahora}"
        )

        self.enviar_texto(chat_id, mensaje)
