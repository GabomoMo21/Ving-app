# notificaciones_config.py
import json
from pathlib import Path
from datetime import datetime, timedelta
import random
import string

CONFIG_PATH = Path("notificaciones_config.json")

def cargar_config_dict():
    if not CONFIG_PATH.exists():
        raise FileNotFoundError("No se encontró notificaciones_config.json")
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)

def guardar_config_dict(cfg: dict):
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

def generar_codigo():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

def preparar_codigo_enlace():
    cfg = cargar_config_dict()
    codigo = generar_codigo()
    expira = datetime.now() + timedelta(minutes=10)
    cfg["codigo_enlace_pendiente"] = codigo
    cfg["codigo_enlace_expira"] = expira.isoformat()
    guardar_config_dict(cfg)
    return codigo, expira
