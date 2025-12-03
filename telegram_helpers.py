# telegram_helpers.py
from notificaciones_config import cargar_config_dict
from telegram_channel import TelegramNotificationChannel


def _normalizar_dispositivo(nombre_crudo: str) -> str:
    """
    Recibe el nombre que venga de la app (QuickActions, simuladores, listas, etc.)
    y lo mapea a un nombre "canónico" que usamos en notificaciones_config.json.
    Así evitamos problemas entre "LPR (placa)", "Reconocimiento de placas", etc.
    """
    if not nombre_crudo:
        return ""

    n = nombre_crudo.strip().lower()

  
    if "lpr" in n or "placa" in n or "placas" in n:
        return "LPR (placa)"

    # Botón de pánico
    if "pánico" in n or "panico" in n:
        return "Botón de pánico"

    # Alarma silenciosa
    if "silenciosa" in n:
        # Si en algún lado se usa "silenciosa" a secas, la mapeamos a Alarma silenciosa
        return "Alarma silenciosa"

    # Puertas y ventanas
    if "puerta" in n or "ventana" in n:
        return "Puertas/ventanas"

    # Cámara
    if "cámara" in n or "camara" in n:
        if "placa" in n or "lpr" in n:
            return "Reconocimiento de placas"
        return "Cámara con foto por movimiento"

    # Humo
    if "humo" in n:
        return "Sensor de humo"

    # Movimiento
    if "movimiento" in n:
        return "Detector de movimiento"

    # Presencia
    if "presencia" in n:
        return "Simulador de presencia"

    # Barrera láser
    if "barrera" in n or "laser" in n or "láser" in n:
        return "Barrera láser"

    # Si no se reconoce, devolvemos el original tal cual
    return nombre_crudo.strip()


def enviar_telegram_si_corresponde(dispositivo: str, severidad: str, titulo: str, cuerpo: str):
    """
    Enviar una notificación de Telegram si:
    - Telegram está habilitado
    - El dispositivo tiene enviar_telegram = true
    - La severidad cumple la severidad mínima configurada

    severidad: 'low', 'medium', 'high', 'critical'
    """

    dispositivo_original = dispositivo or ""
    dispositivo_norm = _normalizar_dispositivo(dispositivo_original)

    print(f"[TG-HELPER] Dispositivo crudo={dispositivo_original!r} -> normalizado={dispositivo_norm!r}, severidad={severidad!r}, titulo={titulo!r}")

    try:
        cfg = cargar_config_dict()
    except Exception as e:
        print("[TG-HELPER] No se pudo cargar config:", e)
        return

    if not cfg.get("telegram_habilitado"):
        print("[TG-HELPER] telegram_habilitado = False, no envío.")
        return

    bot_token = cfg.get("bot_token")
    chat_id = cfg.get("telegram_chat_id")
    if not bot_token or not chat_id:
        print(f"[TG-HELPER] Falta bot_token o chat_id (bot_token={bool(bot_token)}, chat_id={chat_id})")
        return

    dispositivos_cfg = cfg.get("dispositivos", {})
    print(f"[TG-HELPER] Claves en dispositivos:", list(dispositivos_cfg.keys()))

    disp_cfg = dispositivos_cfg.get(dispositivo_norm)
    if not disp_cfg:
        print(f"[TG-HELPER] No hay config para dispositivo {dispositivo_norm!r}")
        return

    if not disp_cfg.get("enviar_telegram", False):
        print(f"[TG-HELPER] enviar_telegram=False para {dispositivo_norm!r}, no envío.")
        return

    severidad_actual = (severidad or "").lower()
    mapa_valor = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    mapa_min = {"INFO": 1, "ALTA": 3, "CRITICA": 4}
    sev_min = (disp_cfg.get("severidad_minima", "ALTA") or "").upper()

    print(f"[TG-HELPER] severidad_actual={severidad_actual}, sev_min={sev_min}")

    # Si es crítico y está activado siempre_enviar_criticos, pasa directo
    if severidad_actual == "critical" and cfg.get("siempre_enviar_criticos", True):
        print("[TG-HELPER] Evento CRITICAL, siempre_enviar_criticos=True -> envío directo.")
    else:
        valor = mapa_valor.get(severidad_actual, 1)
        minimo = mapa_min.get(sev_min, 1)
        print(f"[TG-HELPER] valor={valor}, minimo={minimo}")
        if valor < minimo:
            print("[TG-HELPER] Severidad demasiado baja, no envío.")
            return

    canal = TelegramNotificationChannel(bot_token)
    print("[TG-HELPER] Enviando mensaje a Telegram...")
    canal.enviar_evento(
        chat_id=chat_id,
        dispositivo=dispositivo_norm,
        severidad=severidad_actual,
        titulo=titulo,
        cuerpo=cuerpo
    )
    print("[TG-HELPER] Mensaje enviado (o al menos intentado).")
