# telegram_bot.py
#
# Bot sencillo para vincular la app de Seguridad Ving / Cámara con Telegram.
# - Lee y escribe en notificaciones_config.json
# - Maneja /start y /link CODIGO
# - Guarda telegram_chat_id cuando el código es válido
#
# Requiere: pip install requests

import time
import json
import requests
from pathlib import Path
from datetime import datetime


CONFIG_PATH = Path("notificaciones_config.json")


def cargar_config():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError("No se encontró notificaciones_config.json")
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def guardar_config(cfg: dict):
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def get_api_url(bot_token: str) -> str:
    return f"https://api.telegram.org/bot{bot_token}"


def enviar_mensaje(bot_token: str, chat_id: int, texto: str):
    url = get_api_url(bot_token) + "/sendMessage"
    try:
        requests.get(
            url,
            params={"chat_id": chat_id, "text": texto},
            timeout=5,
        )
    except Exception as e:
        print("Error enviando mensaje:", e)


def manejar_comando_start(bot_token: str, chat_id: int):
    texto = (
        "👋 Hola, soy el bot de Seguridad Ving.\n\n"
        "Para vincular tu app con este chat:\n"
        "1️⃣ Ve a la app de Seguridad Ving (cámara).\n"
        "2️⃣ En el apartado de Notificaciones Telegram, genera un código de enlace.\n"
        "3️⃣ Escríbeme aquí: /link TU_CODIGO\n\n"
        "Ejemplo: /link ABC123"
    )
    enviar_mensaje(bot_token, chat_id, texto)


def manejar_comando_link(bot_token: str, chat_id: int, argumentos: list[str]):
    cfg = cargar_config()

    if not argumentos:
        enviar_mensaje(
            bot_token,
            chat_id,
            "❌ Debes enviar un código. Ejemplo: /link ABC123",
        )
        return

    codigo_usuario = argumentos[0].strip().upper()
    codigo_guardado = cfg.get("codigo_enlace_pendiente")
    expira_str = cfg.get("codigo_enlace_expira")

    if not codigo_guardado:
        enviar_mensaje(
            bot_token,
            chat_id,
            "❌ No hay ningún código de enlace pendiente. Genera uno desde la app.",
        )
        return

    # Verificar expiración, si existe
    if expira_str:
        try:
            expira = datetime.fromisoformat(expira_str)
            if datetime.now() > expira:
                enviar_mensaje(
                    bot_token,
                    chat_id,
                    "❌ Ese código ya expiró. Genera uno nuevo desde la app.",
                )
                cfg["codigo_enlace_pendiente"] = None
                cfg["codigo_enlace_expira"] = None
                guardar_config(cfg)
                return
        except Exception:
            # Si el formato es raro, simplemente seguimos sin validar fecha
            pass

    if codigo_usuario != codigo_guardado:
        enviar_mensaje(
            bot_token,
            chat_id,
            "❌ Código incorrecto. Verifica el código que aparece en la app.",
        )
        return

    # Código correcto: guardamos el chat_id
    cfg["telegram_chat_id"] = chat_id
    cfg["telegram_habilitado"] = True
    cfg["codigo_enlace_pendiente"] = None
    cfg["codigo_enlace_expira"] = None
    guardar_config(cfg)

    enviar_mensaje(
        bot_token,
        chat_id,
        "✅ ¡Listo! Tu app de Seguridad Ving quedó vinculada con este chat.\n"
        "A partir de ahora recibirás aquí las notificaciones configuradas.",
    )


def procesar_update(bot_token: str, update: dict):
    if "message" not in update:
        return

    msg = update["message"]
    chat_id = msg["chat"]["id"]
    text = msg.get("text", "")

    if not text:
        return

    if text.startswith("/start"):
        manejar_comando_start(bot_token, chat_id)
    elif text.startswith("/link"):
        partes = text.split()
        argumentos = partes[1:] if len(partes) > 1 else []
        manejar_comando_link(bot_token, chat_id, argumentos)
    else:
        enviar_mensaje(
            bot_token,
            chat_id,
            "🤖 Comando no reconocido.\nUsa /start para ver instrucciones.",
        )


def main():
    cfg = cargar_config()
    bot_token = cfg.get("bot_token")
    if not bot_token:
        raise RuntimeError(
            "Debes configurar 'bot_token' en notificaciones_config.json "
            "con el token que te dio BotFather."
        )

    api_url = get_api_url(bot_token)
    offset = None

    print("Bot de Seguridad Ving escuchando... (Ctrl+C para salir)")

    while True:
        try:
            resp = requests.get(
                api_url + "/getUpdates",
                params={"timeout": 50, "offset": offset},
                timeout=60,
            )
            data = resp.json()
            if not data.get("ok"):
                print("Error en getUpdates:", data)
                time.sleep(5)
                continue

            for update in data.get("result", []):
                offset = update["update_id"] + 1
                procesar_update(bot_token, update)

        except KeyboardInterrupt:
            print("\nBot detenido por el usuario.")
            break
        except Exception as e:
            print("Error en el loop de getUpdates:", e)
            time.sleep(5)


if __name__ == "__main__":
    main()
