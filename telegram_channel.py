# telegram_channel.py
import os
import requests
from datetime import datetime


class TelegramNotificationChannel:
    """
    Encapsula el envío de mensajes al bot de Telegram.
    """

    def __init__(self, bot_token: str):
        self.bot_token = bot_token
        self.api_url = f"https://api.telegram.org/bot{bot_token}"

    def enviar_texto(self, chat_id: int, texto: str):
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

    def enviar_foto(self, chat_id: int, image_path: str, caption: str | None = None):
        """
        Envía una foto al chat, con un texto opcional (caption).
        """
        if not self.bot_token:
            print("TelegramNotificationChannel: bot_token vacío, no se envía foto.")
            return

        if not image_path or not os.path.exists(image_path):
            print("TelegramNotificationChannel: image_path inválido:", image_path)
            return

        try:
            with open(image_path, "rb") as f:
                files = {"photo": f}
                data = {"chat_id": chat_id}
                if caption:
                    data["caption"] = caption

                requests.post(
                    self.api_url + "/sendPhoto",
                    data=data,
                    files=files,
                    timeout=10,
                )
        except Exception as e:
            print("Error enviando foto a Telegram:", e)

    def enviar_evento(
        self,
        chat_id: int,
        dispositivo: str,
        severidad: str,
        titulo: str,
        cuerpo: str,
        image_path: str | None = None,
    ):
        """
        Envía un mensaje formateado a partir de un evento.
        Si se pasa image_path, intenta enviar foto + caption.
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

        # Si hay imagen válida, la mandamos como foto con caption
        if image_path and os.path.exists(image_path):
            self.enviar_foto(chat_id, image_path, caption=mensaje)
        else:
            self.enviar_texto(chat_id, mensaje)
