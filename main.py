#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ving Desktop — Aplicación de escritorio (Python + Tkinter)
=========================================================

Cumple con los RFs provistos (MVP) usando:
- UI: Tkinter + ttk + ttkbootstrap-like styling (simple)
- DB: SQLite (archivo local `ving.db`)
- Notificaciones: in-app (banner), visual (colores) y sonido (beep)
- Bitácora/histograma: tabla + gráfico (matplotlib opcional si instalado)
- Paginación y búsqueda: en tabla de dispositivos y bitácora
- Programaciones: intervalos guardados en JSON por dispositivo

Para ejecutar:
    python main.py

Dependencias:
    - Python 3.9+
    - Paquetes estándar (sqlite3, json, datetime, etc.)
    - (Opcional) matplotlib para histograma embebido

Nota: Este MVP simula acciones de dispositivos (no controla hardware),
salvo la pestaña Cerraduras que envía comandos reales al Pico si está conectado.
"""

import os
import sys
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List, Tuple
from pico_link import PicoLink

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception:
    print("Tkinter es requerido.")
    raise

# Sonido: beep simple (cross-platform)
try:
    import winsound
    def play_beep(freq=800, dur=200):
        try:
            winsound.Beep(freq, dur)
        except Exception:
            print("[beep]")
except Exception:
    def play_beep(freq=800, dur=200):
        try:
            root = tk._default_root
            if root:
                root.bell()
        except Exception:
            print("[beep]")

# Matplotlib (opcional) para histograma
HAS_MPL = True
try:
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    HAS_MPL = False

DB_PATH = os.path.join(os.path.dirname(__file__), 'ving.db')

# ----------------------------
#   Esquema de datos (SQLite)
# ----------------------------
SCHEMA_SQL = r"""
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_until TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    remember_me INTEGER NOT NULL DEFAULT 0,
    remembered_email TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    alias TEXT NOT NULL,
    type TEXT NOT NULL,
    serial TEXT NOT NULL UNIQUE,
    location TEXT,
    status TEXT NOT NULL DEFAULT 'idle',
    armed INTEGER NOT NULL DEFAULT 0,
    schedules_json TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_id INTEGER,
    ts TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT,
    image_path TEXT,
    extra_json TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ts TEXT NOT NULL,
    channel TEXT NOT NULL,
    priority TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

# ---------------
#   Utilidades
# ---------------
import hashlib

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def utcnow_str() -> str:
    return datetime.utcnow().isoformat()

def parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

# ----------------
#   Repositorio
# ----------------
class Repo:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._ensure_db()

    def _ensure_db(self):
        with sqlite3.connect(self.path) as cx:
            cx.execute("PRAGMA journal_mode=WAL;")
            cx.executescript(SCHEMA_SQL)
            cur = cx.execute("SELECT id FROM settings WHERE id=1")
            if not cur.fetchone():
                cx.execute(
                    "INSERT INTO settings (id, remember_me, remembered_email, created_at) VALUES (1, 0, NULL, ?)",
                    (utcnow_str(),)
                )

    # --- Users ---
    def create_user(self, name: str, email: str, password: str) -> int:
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            try:
                cur = cx.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, hash_password(password))
                )
                return cur.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("El correo ingresado ya está registrado")

    def find_user(self, email: str):
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            cur = cx.execute("SELECT * FROM users WHERE email=?", (email,))
            return cur.fetchone()

    def update_user_failed_attempts(self, user_id: int, failed: int, lock_until: Optional[datetime]):
        with sqlite3.connect(self.path) as cx:
            lock_str = lock_until.isoformat() if lock_until else None
            cx.execute("UPDATE users SET failed_attempts=?, lock_until=? WHERE id=?", (failed, lock_str, user_id))

    def set_remember_me(self, enabled: bool, email: Optional[str]):
        with sqlite3.connect(self.path) as cx:
            cx.execute("UPDATE settings SET remember_me=?, remembered_email=? WHERE id=1",
                       (1 if enabled else 0, email))

    def get_settings(self):
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            cur = cx.execute("SELECT * FROM settings WHERE id=1")
            return cur.fetchone()

    # --- Devices ---
    def add_device(self, user_id: int, alias: str, type_: str, serial: str, location: str) -> int:
        with sqlite3.connect(self.path) as cx:
            try:
                cur = cx.execute(
                    "INSERT INTO devices (user_id, alias, type, serial, location) VALUES (?,?,?,?,?)",
                    (user_id, alias, type_, serial, location)
                )
                return cur.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("El dispositivo con ese número de serie ya está registrado")

    def edit_device(self, device_id: int, alias: str, location: str):
        with sqlite3.connect(self.path) as cx:
            cx.execute("UPDATE devices SET alias=?, location=? WHERE id=?", (alias, location, device_id))

    def set_device_status(self, device_id: int, status: str):
        with sqlite3.connect(self.path) as cx:
            cx.execute("UPDATE devices SET status=? WHERE id=?", (status, device_id))

    def set_device_armed(self, device_id: int, armed: bool):
        with sqlite3.connect(self.path) as cx:
            cx.execute("UPDATE devices SET armed=? WHERE id=?", (1 if armed else 0, device_id))

    def set_device_schedules(self, device_id: int, schedules_json: str):
        with sqlite3.connect(self.path) as cx:
            cx.execute("UPDATE devices SET schedules_json=? WHERE id=?", (schedules_json, device_id))

    def get_device(self, device_id: int):
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            cur = cx.execute("SELECT * FROM devices WHERE id=?", (device_id,))
            return cur.fetchone()

    def list_devices(self, user_id: int, q: str = '', page: int = 1, page_size: int = 10) -> Tuple[List[sqlite3.Row], int]:
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            params = [user_id]
            where = "WHERE user_id=?"
            if q:
                where += " AND (alias LIKE ? OR serial LIKE ? OR type LIKE ?)"
                like = f"%{q}%"
                params += [like, like, like]
            cur = cx.execute(f"SELECT COUNT(*) FROM devices {where}", params)
            total = cur.fetchone()[0]
            offset = (page - 1) * page_size
            cur = cx.execute(
                f"SELECT * FROM devices {where} ORDER BY alias LIMIT ? OFFSET ?",
                params + [page_size, offset]
            )
            return list(cur.fetchall()), total

    # --- Events ---
    def add_event(self, user_id: int, device_id: Optional[int], type_: str, severity: str, message: str, image_path: Optional[str], extra: dict):
        with sqlite3.connect(self.path) as cx:
            cx.execute(
                "INSERT INTO events (user_id, device_id, ts, type, severity, message, image_path, extra_json) VALUES (?,?,?,?,?,?,?,?)",
                (user_id, device_id, utcnow_str(), type_, severity, message, image_path, json.dumps(extra or {}))
            )

    def list_events(self, user_id: int, q: str = '', typ: str = '', severity: str = '', page: int = 1, page_size: int = 20,
                    device_id: Optional[int]=None, date_from: Optional[str]=None, date_to: Optional[str]=None) -> Tuple[List[sqlite3.Row], int]:
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            wh = ["user_id=?"]
            params = [user_id]
            if q:
                wh.append("(message LIKE ?)")
                params.append(f"%{q}%")
            if typ:
                wh.append("type=?")
                params.append(typ)
            if severity:
                wh.append("severity=?")
                params.append(severity)
            if device_id:
                wh.append("device_id=?")
                params.append(device_id)
            if date_from:
                wh.append("ts>=?")
                params.append(date_from)
            if date_to:
                wh.append("ts<?")
                params.append(date_to)
            where = " WHERE " + " AND ".join(wh)
            cur = cx.execute(f"SELECT COUNT(*) FROM events{where}", params)
            total = cur.fetchone()[0]
            offset = (page - 1) * page_size
            cur = cx.execute(
                f"SELECT * FROM events{where} ORDER BY ts DESC LIMIT ? OFFSET ?",
                params + [page_size, offset]
            )
            return list(cur.fetchall()), total

    # --- Notifications ---
    def add_notification(self, user_id: int, channel: str, priority: str, title: str, body: str, status: str):
        with sqlite3.connect(self.path) as cx:
            cx.execute(
                "INSERT INTO notifications (user_id, ts, channel, priority, title, body, status) VALUES (?,?,?,?,?,?,?)",
                (user_id, utcnow_str(), channel, priority, title, body, status)
            )

# ----------------
#   Dominio
# ----------------
@dataclass
class User:
    id: int
    name: str
    email: str

# ----------------
#   UI helpers
# ----------------
class Banner(ttk.Frame):
    """Banner superior para notificaciones in-app (visual)."""
    def __init__(self, master):
        super().__init__(master)
        self.configure(padding=8)
        self._msg = tk.StringVar(value='')
        self._lbl = ttk.Label(self, textvariable=self._msg, anchor='center', font=("Segoe UI", 10, 'bold'))
        self._lbl.pack(fill='x')
        self.hide()

    def show(self, text: str, kind: str = 'info'):
        colors = {
            'info':  ('#e8f1ff', '#0b5ed7'),
            'success': ('#e7f7ed', '#0f5132'),
            'warning': ('#fff3cd', '#664d03'),
            'danger':  ('#f8d7da', '#842029'),
            'priority':('#ffe5e5', '#a80000'),
        }
        bg, fg = colors.get(kind, colors['info'])
        self._msg.set(text)
        self._lbl.configure(background=bg, foreground=fg)
        self.configure(style='Banner.TFrame')
        self.pack(fill='x', side='top')
        play_beep(1000 if kind in ('danger','priority') else 700, 200)
        self.after(2500, self.hide)

    def hide(self):
        self.pack_forget()

class Paginator(ttk.Frame):
    def __init__(self, master, on_page, page_size=10):
        super().__init__(master)
        self.on_page = on_page
        self.page = 1
        self.total = 0
        self.page_size = page_size
        self.lbl = ttk.Label(self, text="")
        self.btn_prev = ttk.Button(self, text="◀", width=3, command=self.prev)
        self.btn_next = ttk.Button(self, text="▶", width=3, command=self.next)
        self.btn_prev.pack(side='left')
        self.btn_next.pack(side='left')
        self.lbl.pack(side='left', padx=8)

    def update_numbers(self, page, total):
        self.page = max(1, page)
        self.total = total
        pages = 1 if self.total == 0 else (self.total + self.page_size - 1)//self.page_size
        self.lbl.configure(text=f"Página {self.page} de {pages} — {self.total} registros")
        self.btn_prev['state'] = 'normal' if self.page>1 else 'disabled'
        self.btn_next['state'] = 'normal' if self.page * self.page_size < self.total else 'disabled'

    def prev(self):
        if self.page>1:
            self.on_page(self.page-1)

    def next(self):
        if self.page * self.page_size < self.total:
            self.on_page(self.page+1)

# --------------
#   Vistas
# --------------
class LoginView(ttk.Frame):
    MAX_ATTEMPTS = 5

    def __init__(self, master, repo: Repo, on_login):
        super().__init__(master)
        self.repo = repo
        self.on_login = on_login
        self.pack(fill='both', expand=True)

        self.banner = Banner(self)

        frm = ttk.Frame(self, padding=20)
        frm.pack(expand=True)
        ttk.Label(frm, text="Ving — Inicio de sesión", font=("Segoe UI", 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=8)

        ttk.Label(frm, text="Correo").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Contraseña").grid(row=2, column=0, sticky='e', padx=5, pady=5)

        self.ent_email = ttk.Entry(frm, width=32)
        self.ent_pass = ttk.Entry(frm, show='*', width=32)
        self.ent_email.grid(row=1, column=1, pady=5)
        self.ent_pass.grid(row=2, column=1, pady=5)

        self.var_rem = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(frm, text="Mantener sesión iniciada", variable=self.var_rem)
        chk.grid(row=3, column=1, sticky='w', pady=5)

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(btns, text="Iniciar sesión", command=self.login).pack(side='left', padx=5)
        ttk.Button(btns, text="Crear cuenta", command=self.open_register).pack(side='left', padx=5)

        st = self.repo.get_settings()
        if st and st['remember_me'] and st['remembered_email']:
            self.ent_email.insert(0, st['remembered_email'])
            self.var_rem.set(True)

    def open_register(self):
        RegisterDialog(self, self.repo, on_ok=lambda email: self.ent_email.delete(0,'end') or self.ent_email.insert(0,email) or self.banner.show("Registro exitoso. Ahora inicia sesión.", 'success'))

    def login(self):
        email = self.ent_email.get().strip().lower()
        pw = self.ent_pass.get()
        if not email or not pw:
            self.banner.show("Completa correo y contraseña.", 'warning')
            return
        row = self.repo.find_user(email)
        if not row:
            self.banner.show("Usuario o contraseña incorrectos", 'danger'); play_beep(1200, 250); return

        lock_until = parse_dt(row['lock_until']) if row['lock_until'] else None
        if lock_until and datetime.utcnow() < lock_until:
            secs = int((lock_until - datetime.utcnow()).total_seconds())
            self.banner.show(f"Cuenta bloqueada. Intenta en {secs}s", 'danger')
            return

        if row['password_hash'] != hash_password(pw):
            failed = row['failed_attempts'] + 1
            lock = None
            if failed >= self.MAX_ATTEMPTS:
                lock = datetime.utcnow() + timedelta(minutes=5)
                failed = 0
            self.repo.update_user_failed_attempts(row['id'], failed, lock)
            self.banner.show("Usuario o contraseña incorrectos", 'danger'); play_beep(1200, 250); return

        self.repo.update_user_failed_attempts(row['id'], 0, None)
        self.repo.set_remember_me(self.var_rem.get(), email if self.var_rem.get() else None)
        user = User(id=row['id'], name=row['name'], email=row['email'])
        self.on_login(user)

class RegisterDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, on_ok=None):
        super().__init__(master)
        self.title("Crear cuenta")
        self.repo = repo
        self.on_ok = on_ok
        self.resizable(False, False)
        self.grab_set()

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill='both', expand=True)
        ttk.Label(frm, text="Nombre completo").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Correo").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Contraseña").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Confirmar contraseña").grid(row=3, column=0, sticky='e', padx=5, pady=5)

        self.e_name = ttk.Entry(frm, width=34)
        self.e_mail = ttk.Entry(frm, width=34)
        self.e_pw1 = ttk.Entry(frm, show='*', width=34)
        self.e_pw2 = ttk.Entry(frm, show='*', width=34)
        self.e_name.grid(row=0, column=1, pady=5)
        self.e_mail.grid(row=1, column=1, pady=5)
        self.e_pw1.grid(row=2, column=1, pady=5)
        self.e_pw2.grid(row=3, column=1, pady=5)

        ttk.Button(frm, text="Crear", command=self.create).grid(row=4, column=0, columnspan=2, pady=10)

    def create(self):
        name = self.e_name.get().strip()
        email = self.e_mail.get().strip().lower()
        pw1 = self.e_pw1.get()
        pw2 = self.e_pw2.get()
        if not name or not email or not pw1 or not pw2:
            messagebox.showwarning("Campos", "Completa todos los campos"); return
        if len(pw1) < 8 or not any(c.isupper() for c in pw1) or not any(c.isdigit() for c in pw1) or not any(not c.isalnum() for c in pw1):
            messagebox.showerror("Contraseña", "La contraseña debe tener mínimo 8 caracteres, incluir una mayúscula, un número y un símbolo."); return
        if pw1 != pw2:
            messagebox.showerror("Contraseña", "Las contraseñas no coinciden"); return
        try:
            self.repo.create_user(name, email, pw1)
        except ValueError as ex:
            messagebox.showerror("Registro", str(ex)); return
        messagebox.showinfo("Registro", "Cuenta creada exitosamente")
        if self.on_ok: self.on_ok(email)
        self.destroy()

class DevicesTab(ttk.Frame):
    TYPES = [
        "Detector de movimiento",
        "Cerradura remota",
        "Sensor de humo",
        "Cámara con foto por movimiento",
        "Simulador de presencia",
        "Botón de pánico",
        "Puertas/ventanas",
        "Alarma silenciosa",
        "Barrera láser",
        "Reconocimiento de placas",
    ]

    def __init__(self, master, repo: Repo, user: User, banner: Banner, on_event):
        super().__init__(master)
        self.repo = repo
        self.user = user
        self.banner = banner
        self.on_event = on_event
        self.q = ''
        self.page = 1
        self.page_size = 10

        top = ttk.Frame(self)
        top.pack(fill='x', padx=8, pady=6)
        ttk.Label(top, text="Buscar (alias/serie/tipo):").pack(side='left')
        self.e_search = ttk.Entry(top, width=30); self.e_search.pack(side='left', padx=5)
        ttk.Button(top, text="Buscar", command=self._do_search).pack(side='left')
        ttk.Button(top, text="Limpiar", command=self._clear_search).pack(side='left', padx=5)
        ttk.Button(top, text="➕ Registrar dispositivo", command=self._open_add).pack(side='right')

        cols = ("alias","type","serial","status","location","armed")
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=12)
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, anchor='center', width=130)
        self.tree.pack(fill='both', expand=True, padx=8)
        self.tree.bind('<Double-1>', self._open_edit)

        self.pag = Paginator(self, on_page=self._goto_page, page_size=self.page_size)
        self.pag.pack(fill='x', padx=8, pady=4)

        act = ttk.Frame(self); act.pack(fill='x', padx=8, pady=6)
        ttk.Button(act, text="Editar alias/ubicación", command=self._open_edit).pack(side='left')
        ttk.Button(act, text="Armado/Desarmado", command=self._toggle_arm).pack(side='left', padx=6)
        ttk.Button(act, text="Configurar horarios", command=self._open_sched).pack(side='left', padx=6)

        self.refresh()

    def _do_search(self):
        self.q = self.e_search.get().strip(); self.page = 1; self.refresh()

    def _clear_search(self):
        self.e_search.delete(0,'end'); self.q = ''; self.page = 1; self.refresh()

    def _goto_page(self, p):
        self.page = p; self.refresh()

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows, total = self.repo.list_devices(self.user.id, q=self.q, page=self.page, page_size=self.page_size)
        for r in rows:
            self.tree.insert('', 'end', iid=str(r['id']),
                             values=(r['alias'], r['type'], r['serial'], r['status'], r['location'], 'Armado' if r['armed'] else 'Desarmado'))
        self.pag.update_numbers(self.page, total)

    def _selected_id(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel:
            self.banner.show("Selecciona un dispositivo", 'warning'); return None
        return int(sel[0])

    def _open_add(self):
        DeviceAddDialog(self, self.repo, self.user,
                        on_saved=lambda: (self.banner.show("Dispositivo registrado", 'success'), play_beep(900, 120), self.refresh()))

    def _open_edit(self, *_):
        did = self._selected_id()
        if not did: return
        DeviceEditDialog(self, self.repo, device_id=did,
                         on_saved=lambda: (self.banner.show("Dispositivo actualizado", 'success'), self.refresh()))

    def _toggle_arm(self):
        did = self._selected_id()
        if not did: return
        row = self.repo.get_device(did)
        newv = not bool(row['armed'])
        self.repo.set_device_armed(did, newv)
        state = 'Armado' if newv else 'Desarmado'
        self.banner.show(f"{row['alias']}: {state}", 'info')
        self.repo.add_event(self.user.id, did, type_='arm_state', severity='low',
                            message=f"Sistema {state.lower()}", image_path=None, extra={})
        self.refresh()

    def _open_sched(self):
        did = self._selected_id()
        if not did: return
        ScheduleDialog(self, self.repo, device_id=did,
                       on_saved=lambda: self.banner.show("Horarios actualizados", 'success'))

class DeviceAddDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, user: User, on_saved=None):
        super().__init__(master)
        self.title("Registrar dispositivo por número de serie")
        self.repo = repo; self.user = user; self.on_saved = on_saved
        self.resizable(False, False); self.grab_set()

        frm = ttk.Frame(self, padding=12); frm.pack(fill='both', expand=True)
        ttk.Label(frm, text="Número de serie").grid(row=0, column=0, sticky='e', padx=6, pady=6)
        ttk.Label(frm, text="Tipo").grid(row=1, column=0, sticky='e', padx=6, pady=6)
        ttk.Label(frm, text="Alias").grid(row=2, column=0, sticky='e', padx=6, pady=6)
        ttk.Label(frm, text="Ubicación").grid(row=3, column=0, sticky='e', padx=6, pady=6)

        self.e_serial = ttk.Entry(frm, width=34)
        self.cb_type = ttk.Combobox(frm, values=DevicesTab.TYPES, state='readonly', width=31)
        self.e_alias = ttk.Entry(frm, width=34)
        self.e_loc = ttk.Entry(frm, width=34)
        self.cb_type.current(0)

        self.e_serial.grid(row=0, column=1, pady=6)
        self.cb_type.grid(row=1, column=1, pady=6)
        self.e_alias.grid(row=2, column=1, pady=6)
        self.e_loc.grid(row=3, column=1, pady=6)

        ttk.Button(frm, text="Registrar", command=self._save).grid(row=4, column=0, columnspan=2, pady=10)

    def _save(self):
        serial = self.e_serial.get().strip()
        type_ = self.cb_type.get()
        alias = self.e_alias.get().strip() or type_
        loc = self.e_loc.get().strip()
        if not serial:
            messagebox.showwarning("Validación", "Ingresa el número de serie"); return
        try:
            self.repo.add_device(self.user.id, alias, type_, serial, loc)
        except ValueError as ex:
            messagebox.showerror("Registro", str(ex)); return
        play_beep(900, 120)
        if self.on_saved: self.on_saved()
        self.destroy()

class DeviceEditDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, device_id: int, on_saved=None):
        super().__init__(master)
        self.title("Editar alias y ubicación")
        self.repo = repo; self.device_id = device_id; self.on_saved = on_saved
        self.resizable(False, False); self.grab_set()

        row = self.repo.get_device(device_id)

        frm = ttk.Frame(self, padding=12); frm.pack(fill='both', expand=True)
        ttk.Label(frm, text="Alias").grid(row=0, column=0, sticky='e', padx=6, pady=6)
        ttk.Label(frm, text="Ubicación").grid(row=1, column=0, sticky='e', padx=6, pady=6)

        self.e_alias = ttk.Entry(frm, width=34)
        self.e_loc = ttk.Entry(frm, width=34)
        self.e_alias.insert(0, row['alias'])
        self.e_loc.insert(0, row['location'] or '')
        self.e_alias.grid(row=0, column=1, pady=6)
        self.e_loc.grid(row=1, column=1, pady=6)
        ttk.Button(frm, text="Guardar", command=self._save).grid(row=2, column=0, columnspan=2, pady=10)

    def _save(self):
        alias = self.e_alias.get().strip()
        loc = self.e_loc.get().strip()
        if not alias:
            messagebox.showwarning("Validación", "El alias no puede estar vacío"); return
        self.repo.edit_device(self.device_id, alias, loc)
        if self.on_saved: self.on_saved()
        self.destroy()

class ScheduleDialog(tk.Toplevel):
    """Programaciones de horario por dispositivo. Guarda como lista JSON [{"start":"HH:MM","end":"HH:MM"}, ...]"""
    def __init__(self, master, repo: Repo, device_id: int, on_saved=None):
        super().__init__(master)
        self.title("Programaciones de horario")
        self.repo = repo; self.device_id = device_id; self.on_saved = on_saved
        self.resizable(False, False); self.grab_set()

        row = self.repo.get_device(device_id)
        self.schedules = json.loads(row['schedules_json'] or '[]')

        frm = ttk.Frame(self, padding=12); frm.pack(fill='both', expand=True)
        ttk.Label(frm, text=f"Dispositivo: {row['alias']} — {row['type']}").pack(anchor='w')

        self.listbox = tk.Listbox(frm, width=40, height=8); self.listbox.pack(pady=6, fill='x')
        self._reload_list()

        edit = ttk.Frame(frm); edit.pack(fill='x', pady=6)
        ttk.Label(edit, text="Inicio (HH:MM)").pack(side='left')
        self.e_start = ttk.Entry(edit, width=7); self.e_start.pack(side='left', padx=4)
        ttk.Label(edit, text="Fin (HH:MM)").pack(side='left')
        self.e_end = ttk.Entry(edit, width=7); self.e_end.pack(side='left', padx=4)
        ttk.Button(edit, text="Agregar", command=self._add).pack(side='left', padx=6)
        ttk.Button(edit, text="Eliminar", command=self._del).pack(side='left')

        ttk.Button(frm, text="Guardar", command=self._save).pack(pady=8)

    def _reload_list(self):
        self.listbox.delete(0,'end')
        for it in self.schedules:
            self.listbox.insert('end', f"{it['start']} - {it['end']}")

    @staticmethod
    def _valid_hhmm(s: str) -> bool:
        try:
            datetime.strptime(s, '%H:%M'); return True
        except Exception:
            return False

    def _conflicts(self, news: List[dict]) -> Optional[Tuple[int,int]]:
        def to_min(x):
            h,m = map(int, x.split(':'))
            return h*60+m
        ranges = [(to_min(i['start']), to_min(i['end'])) for i in news]
        ranges.sort()
        for i in range(1, len(ranges)):
            if ranges[i][0] < ranges[i-1][1]:
                return ranges[i-1], ranges[i]
        return None

    def _add(self):
        s = self.e_start.get().strip()
        e = self.e_end.get().strip()
        if not (self._valid_hhmm(s) and self._valid_hhmm(e)):
            messagebox.showerror("Hora", "Usa formato HH:MM"); return
        if s >= e:
            messagebox.showerror("Rango", "El inicio debe ser menor que el fin"); return
        tmp = self.schedules + [{"start":s, "end":e}]
        c = self._conflicts(tmp)
        if c:
            messagebox.showerror("Conflicto", "Existe un solapamiento entre horarios definidos"); return
        self.schedules.append({"start":s, "end":e})
        self._reload_list()

    def _del(self):
        sel = self.listbox.curselection()
        if not sel: return
        self.schedules.pop(sel[0])
        self._reload_list()

    def _save(self):
        self.repo.set_device_schedules(self.device_id, json.dumps(self.schedules))
        if self.on_saved: self.on_saved()
        self.destroy()

class EventsTab(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master)
        self.repo = repo; self.user = user; self.banner = banner
        self.q = ''; self.page = 1; self.page_size = 20

        filt = ttk.Frame(self); filt.pack(fill='x', padx=8, pady=6)
        ttk.Label(filt, text="Buscar").pack(side='left')
        self.e_q = ttk.Entry(filt, width=24); self.e_q.pack(side='left', padx=5)
        ttk.Label(filt, text="Tipo").pack(side='left', padx=(12,4))
        self.e_type = ttk.Entry(filt, width=16); self.e_type.pack(side='left')
        ttk.Label(filt, text="Severidad").pack(side='left', padx=(12,4))
        self.e_sev = ttk.Combobox(filt, values=['','low','medium','high','critical'], width=10, state='readonly')
        self.e_sev.current(0); self.e_sev.pack(side='left')
        ttk.Button(filt, text="Filtrar", command=self._do_filter).pack(side='left', padx=6)
        ttk.Button(filt, text="Limpiar", command=self._clear).pack(side='left')

        cols = ("ts","type","severity","device","location","message")
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=14)
        for c, w in zip(cols, (160,120,100,160,120,400)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor='center' if c!="message" else 'w')
        self.tree.pack(fill='both', expand=True, padx=8)

        self.tree.bind('<ButtonRelease-1>', self._colorize_rows)

        self.pag = Paginator(self, on_page=self._goto, page_size=self.page_size)
        self.pag.pack(fill='x', padx=8, pady=6)

        act = ttk.Frame(self); act.pack(fill='x', padx=8, pady=6)
        ttk.Button(act, text="Ver detalle", command=self._open_detail).pack(side='left')

        self.refresh()

    def _do_filter(self):
        self.q = self.e_q.get().strip(); self.page = 1; self.refresh()

    def _clear(self):
        self.e_q.delete(0,'end'); self.e_type.delete(0,'end'); self.e_sev.current(0)
        self.q = ''; self.page = 1; self.refresh()

    def _goto(self, p):
        self.page = p; self.refresh()

    def refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows, total = self.repo.list_events(self.user.id, q=self.q, typ=self.e_type.get().strip(),
                                            severity=self.e_sev.get().strip(), page=self.page, page_size=self.page_size)
        for r in rows:
            device = ''; location = ''
            if r['device_id']:
                d = self.repo.get_device(r['device_id'])
                if d:
                    device = d['alias']; location = d['location'] or ''
            iid = str(r['id'])
            self.tree.insert('', 'end', iid=iid,
                             values=(r['ts'], r['type'], r['severity'], device, location, r['message']))
            if r['severity'] in ('high','critical'):
                self.tree.tag_configure('critical', background='#ffe5e5')
                self.tree.item(iid, tags=('critical',))
        self.pag.update_numbers(self.page, total)

    def _colorize_rows(self, *_): pass

    def _selected(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel:
            self.banner.show("Selecciona un evento", 'warning'); return None
        return int(sel[0])

    def _open_detail(self):
        eid = self._selected()
        if not eid: return
        EventDetailDialog(self, self.repo, eid)

class EventDetailDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, event_id: int):
        super().__init__(master)
        self.title("Detalle de evento")
        self.repo = repo
        self.resizable(False, False)
        self.grab_set()
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            cur = cx.execute("SELECT * FROM events WHERE id=?", (event_id,))
            ev = cur.fetchone()
        frm = ttk.Frame(self, padding=12); frm.pack(fill='both', expand=True)
        values = [
            ("Fecha/Hora", ev['ts']),
            ("Tipo", ev['type']),
            ("Severidad", ev['severity']),
            ("Mensaje", ev['message'] or ''),
            ("Imagen", ev['image_path'] or '(sin imagen)'),
        ]
        r=0
        for k,v in values:
            ttk.Label(frm, text=k+":", width=16).grid(row=r, column=0, sticky='e', padx=6, pady=4)
            ttk.Label(frm, text=str(v)).grid(row=r, column=1, sticky='w'); r+=1
        if ev['image_path'] and os.path.exists(ev['image_path']):
            try:
                from PIL import Image, ImageTk
                img = Image.open(ev['image_path']); img.thumbnail((360,360))
                tkimg = ImageTk.PhotoImage(img)
                lbl = ttk.Label(frm, image=tkimg); lbl.image = tkimg
                lbl.grid(row=r, column=0, columnspan=2, pady=8)
            except Exception:
                pass
        ttk.Button(frm, text="Cerrar", command=self.destroy).grid(row=r+1, column=0, columnspan=2, pady=8)

class HistogramTab(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master)
        self.repo = repo; self.user = user; self.banner = banner

        ctr = ttk.Frame(self); ctr.pack(fill='x', padx=8, pady=6)
        ttk.Label(ctr, text="Dispositivo (opcional ID)").pack(side='left')
        self.e_dev = ttk.Entry(ctr, width=8); self.e_dev.pack(side='left', padx=4)
        ttk.Label(ctr, text="Desde (YYYY-MM-DD)").pack(side='left', padx=(10,4))
        self.e_from = ttk.Entry(ctr, width=12); self.e_from.pack(side='left')
        ttk.Label(ctr, text="Hasta (YYYY-MM-DD)").pack(side='left', padx=(10,4))
        self.e_to = ttk.Entry(ctr, width=12); self.e_to.pack(side='left')
        ttk.Button(ctr, text="Generar", command=self._plot).pack(side='left', padx=6)

        self.canvas = None
        if not HAS_MPL:
            ttk.Label(self, text="Instala matplotlib para ver el histograma.").pack(pady=12)

    def _plot(self):
        if not HAS_MPL:
            try:
                from matplotlib.figure import Figure
                from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            except Exception as e:
                self.banner.show(f"matplotlib no disponible: {e.__class__.__name__}", 'warning'); return
        device_id = int(self.e_dev.get()) if self.e_dev.get().strip().isdigit() else None
        date_from = self.e_from.get().strip() or None
        date_to = self.e_to.get().strip() or None
        rows, _ = self.repo.list_events(self.user.id, page=1, page_size=10000,
                                        device_id=device_id, date_from=date_from, date_to=date_to)
        counts = {}; days = []
        if date_from and date_to:
            try:
                d0 = datetime.fromisoformat(date_from); d1 = datetime.fromisoformat(date_to)
                cur = d0
                while cur <= d1:
                    key = cur.strftime('%Y-%m-%d')
                    counts[key] = 0; days.append(key)
                    cur += timedelta(days=1)
            except Exception:
                pass
        for r in rows:
            key = r['ts'][:10]
            counts[key] = counts.get(key, 0) + 1
            if key not in days: days.append(key)
        days.sort()
        vals = [counts.get(d,0) for d in days]
        fig = Figure(figsize=(7,3), dpi=100)
        ax = fig.add_subplot(111)
        ax.bar(days, vals)
        ax.set_title('Eventos por día')
        ax.set_ylabel('# eventos')
        ax.set_xticklabels(days, rotation=30, ha='right')
        if self.canvas:
            self.canvas.get_tk_widget().destroy()
        self.canvas = FigureCanvasTkAgg(fig, master=self)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill='both', expand=True, padx=8, pady=8)

class NotificationsTab(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master)
        self.repo = repo; self.user = user; self.banner = banner

        ttk.Label(self, text="Canales (solo in-app en este MVP)").pack(anchor='w', padx=8, pady=6)
        self.var_inapp = tk.BooleanVar(value=True)
        chk = ttk.Checkbutton(self, text="In-app", variable=self.var_inapp); chk.pack(anchor='w', padx=12)

        ttk.Label(self, text="Probar notificación:").pack(anchor='w', padx=8, pady=(12,4))
        test = ttk.Frame(self); test.pack(fill='x', padx=8)
        self.cb_priority = ttk.Combobox(test, values=['normal','alta'], state='readonly', width=10)
        self.cb_priority.current(0)
        self.e_title = ttk.Entry(test, width=24)
        self.e_body = ttk.Entry(test, width=40)
        ttk.Label(test, text="Prioridad").pack(side='left')
        self.cb_priority.pack(side='left', padx=4)
        ttk.Label(test, text="Título").pack(side='left', padx=(12,4))
        self.e_title.pack(side='left')
        ttk.Label(test, text="Mensaje").pack(side='left', padx=(12,4))
        self.e_body.pack(side='left')
        ttk.Button(test, text="Enviar", command=self._send).pack(side='left', padx=6)

    def _send(self):
        if not self.var_inapp.get():
            self.banner.show("Activa al menos un canal", 'warning'); return
        priority = self.cb_priority.get()
        title = self.e_title.get().strip() or 'Prueba'
        body = self.e_body.get().strip() or 'Mensaje de prueba'
        kind = 'priority' if priority=='alta' else 'info'
        self.banner.show(f"{title}: {body}", kind)
        self.repo.add_notification(self.user.id, channel='inapp', priority=priority, title=title, body=body, status='sent')
        self.repo.add_event(self.user.id, device_id=None, type_='notification',
                            severity='high' if priority=='alta' else 'low', message=f"Notif: {title}", image_path=None, extra={})

# -------------------------------
#   NUEVA PESTAÑA: Cerraduras
# -------------------------------
class LockTab(ttk.Frame):
    """Control dedicado de cerradura por hardware (Pico)."""
    def __init__(self, master, repo: Repo, user: User, banner: Banner, pico=None):
        super().__init__(master)
        self.repo = repo
        self.user = user
        self.banner = banner
        self.pico = pico

        info = ttk.Frame(self, padding=10)
        info.pack(fill='x')
        ttk.Label(info, text="Control de cerradura (0° = abrir, 90° = cerrar)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")

        btns = ttk.Frame(self, padding=10); btns.pack(fill='x')
        ttk.Button(btns, text="Abrir (HW)", command=self._open_hw).pack(side="left", padx=6, pady=6)
        ttk.Button(btns, text="Cerrar (HW)", command=self._close_hw).pack(side="left", padx=6, pady=6)

        self.state_lbl = ttk.Label(self, text="Estado: —", padding=10)
        self.state_lbl.pack(anchor="w")

    def _pick_device(self) -> Optional[int]:
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            cur = cx.execute(
                "SELECT id FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",
                (self.user.id, "Cerradura remota")
            )
            r = cur.fetchone()
            return r['id'] if r else None

    def _open_hw(self):
        if not self.pico:
            self.banner.show("Pico no conectado por USB", 'danger'); return
        ok = self.pico.lock_open()
        if not ok:
            self.banner.show("No se pudo abrir la cerradura (HW)", 'danger'); return
        did = self._pick_device()
        if did: self.repo.set_device_status(did, 'unlocked')
        self.repo.add_event(self.user.id, did, 'lock', 'low', "Cerradura unlocked [HW]", None, {"by":"desktop"})
        self.banner.show("Cerradura abierta (0°)", 'success')
        self.state_lbl.config(text="Estado: abierta (0°)")
        play_beep(880, 140)

    def _close_hw(self):
        if not self.pico:
            self.banner.show("Pico no conectado por USB", 'danger'); return
        ok = self.pico.lock_close()
        if not ok:
            self.banner.show("No se pudo cerrar la cerradura (HW)", 'danger'); return
        did = self._pick_device()
        if did: self.repo.set_device_status(did, 'locked')
        self.repo.add_event(self.user.id, did, 'lock', 'low', "Cerradura locked [HW]", None, {"by":"desktop"})
        self.banner.show("Cerradura cerrada (90°)", 'success')
        self.state_lbl.config(text="Estado: cerrada (90°)")
        play_beep(740, 140)

# --------------------------
#   Simulador (sin cerradura)
# --------------------------
class QuickActions(ttk.Frame):
    """Acciones rápidas para simular eventos de dispositivos (cerradura movida a pestaña propia)."""
    def __init__(self, master, repo: Repo, user: User, banner: Banner, pico=None):
        super().__init__(master)
        self.repo = repo; self.user = user; self.banner = banner; self.pico = pico

        ttk.Label(self, text="Simulador de dispositivos (para pruebas)", font=("Segoe UI", 10, 'bold')).pack(anchor='w', padx=8, pady=(8,0))
        grid = ttk.Frame(self); grid.pack(fill='x', padx=8, pady=6)

        buttons = [
            ("Detector movimiento", self.detect_motion),
            ("Humo detectado", self.smoke_alert),
            ("Cámara: foto por mov.", self.camera_capture),
            ("Simulador presencia", self.presence_tick),
            ("Botón de pánico", self.panic_button),
            ("Puerta/ventana cambio", self.door_window_toggle),
            ("Alarma silenciosa", self.silent_alarm),
            ("Barrera láser", self.laser_barrier),
            ("LPR (placa)", self.lpr_event),
        ]
        for i,(txt,cmd) in enumerate(buttons):
            ttk.Button(grid, text=txt, command=cmd).grid(row=i//2, column=i%2, sticky='ew', padx=4, pady=4)
        for c in range(2):
            grid.columnconfigure(c, weight=1)

    def _pick_device(self, type_hint: Optional[str]=None) -> Optional[int]:
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            if type_hint:
                cur = cx.execute("SELECT id, alias FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",
                                 (self.user.id, type_hint))
                r = cur.fetchone()
                if r: return r['id']
            cur = cx.execute("SELECT id FROM devices WHERE user_id=? ORDER BY id LIMIT 1", (self.user.id,))
            r = cur.fetchone()
            return r['id'] if r else None

    def _notify(self, title: str, body: str, priority=False):
        self.repo.add_notification(self.user.id, 'inapp', 'alta' if priority else 'normal', title, body, 'sent')
        self.banner.show(f"{title}: {body}", 'priority' if priority else 'info')

    def detect_motion(self):
        did = self._pick_device("Detector de movimiento")
        self.repo.add_event(self.user.id, did, 'motion', 'high', 'Movimiento detectado', None, {})
        self._notify('Movimiento', 'Se detectó movimiento', priority=True); play_beep(1200, 250)

    def smoke_alert(self):
        did = self._pick_device("Sensor de humo")
        self.repo.add_event(self.user.id, did, 'smoke', 'critical', 'Humo detectado', None, {})
        self._notify('Humo', '¡Alerta crítica!', priority=True); play_beep(1400, 300)

    def camera_capture(self):
        did = self._pick_device("Cámara con foto por movimiento")
        img_path = self._generate_placeholder_image()
        self.repo.add_event(self.user.id, did, 'camera', 'high', 'Foto capturada por movimiento', img_path, {})
        self._notify('Cámara', 'Imagen adjunta')

    def presence_tick(self):
        did = self._pick_device("Simulador de presencia")
        self.repo.add_event(self.user.id, did, 'presence', 'low', 'Simulador accionó luz', None, {})
        self._notify('Presencia', 'Luz conmutada')

    def panic_button(self):
        did = self._pick_device("Botón de pánico")
        self.repo.add_event(self.user.id, did, 'panic', 'critical', 'Botón de pánico activado', None, {})
        self._notify('Pánico', 'Alerta urgente', priority=True); play_beep(1600, 400)

    def door_window_toggle(self):
        did = self._pick_device("Puertas/ventanas")
        row = self.repo.get_device(did) if did else None
        new_state = 'open' if (row and row['status']!='open') else 'closed'
        if did: self.repo.set_device_status(did, new_state)
        self.repo.add_event(self.user.id, did, 'doorwin', 'medium', f"Estado {new_state}", None, {})
        self._notify('Puerta/Ventana', f"{new_state}")

    def silent_alarm(self):
        did = self._pick_device("Alarma silenciosa")
        self.repo.add_event(self.user.id, did, 'silent_alarm', 'critical', 'Alarma silenciosa activada', None, {})
        self.banner.show("Alarma silenciosa: alerta enviada", 'priority')
        self.repo.add_notification(self.user.id, 'inapp', 'alta', 'Alarma silenciosa', 'Alerta enviada', 'sent')

    def laser_barrier(self):
        did = self._pick_device("Barrera láser")
        self.repo.add_event(self.user.id, did, 'laser_start', 'high', 'Barrera interrumpida (inicio)', None, {})
        self._notify('Barrera láser', 'Interrupción detectada')
        def end_event():
            self.repo.add_event(self.user.id, did, 'laser_end', 'high', 'Barrera interrumpida (fin)', None, {"duration_s":2})
        threading.Timer(2.0, end_event).start()

    def lpr_event(self):
        did = self._pick_device("Reconocimiento de placas")
        plate = "ABC123"  # simulado
        authorized = False
        msg = f"Placa {plate} {'autorizada' if authorized else 'NO autorizada'}"
        self.repo.add_event(self.user.id, did, 'lpr', 'high' if not authorized else 'low', msg, None, {"plate": plate, "authorized": authorized})
        if not authorized:
            self._notify('LPR', 'Vehículo no registrado', priority=True)

    def _generate_placeholder_image(self) -> str:
        from PIL import Image, ImageDraw, ImageFont
        os.makedirs('captures', exist_ok=True)
        path = os.path.join('captures', f"capture_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png")
        img = Image.new('RGB', (640, 360), color=(240,240,240))
        d = ImageDraw.Draw(img)
        text = "Captura simulada\nVing"
        d.rectangle([10,10,630,350], outline=(0,0,0))
        try:
            fnt = ImageFont.truetype("arial.ttf", 24)
        except Exception:
            fnt = None
        d.text((40,150), text, fill=(20,20,20), font=fnt)
        img.save(path)
        return path

class MainView(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, pico=None):
        super().__init__(master)
        self.master.title("Ving — Panel principal")
        self.repo = repo
        self.user = user
        self.pico = pico   # <-- se inyecta desde App

        self.banner = Banner(self)

        nb = ttk.Notebook(self); nb.pack(fill='both', expand=True, padx=4, pady=4)

        self.tab_devices = DevicesTab(nb, self.repo, self.user, self.banner, on_event=self._on_event)
        self.tab_events  = EventsTab(nb, self.repo, self.user, self.banner)
        self.tab_hist    = HistogramTab(nb, self.repo, self.user, self.banner)
        self.tab_notif   = NotificationsTab(nb, self.repo, self.user, self.banner)
        self.tab_lock    = LockTab(nb, self.repo, self.user, self.banner, pico=self.pico)  # NUEVA pestaña
        self.tab_quick   = QuickActions(nb, self.repo, self.user, self.banner, pico=self.pico)

        nb.add(self.tab_devices, text='Dispositivos')
        nb.add(self.tab_events,  text='Bitácora')
        nb.add(self.tab_hist,    text='Histograma')
        nb.add(self.tab_notif,   text='Notificaciones')
        nb.add(self.tab_lock,    text='Cerraduras')    # nombre solicitado
        nb.add(self.tab_quick,   text='Simulador')

        # Header (fuera del Notebook, arriba)
        hdr = ttk.Frame(self, padding=6)
        hdr.pack(fill='x', side='top')
        ttk.Label(hdr, text=f"Bienvenido, {user.name}", font=("Segoe UI", 12, 'bold')).pack(side='left')
        ttk.Button(hdr, text="Cerrar sesión", command=self._logout).pack(side='right')

        self.pack(fill='both', expand=True)

    def _logout(self):
        if messagebox.askyesno("Salir", "¿Cerrar sesión?"):
            self.master.destroy()
            main()

    def _on_event(self, *args, **kwargs):
        self.tab_events.refresh()

# --------------
#   App
# --------------
class App(tk.Tk):
    def __init__(self, repo: Repo):
        super().__init__()
        self.geometry('980x720')
        self.title('Ving')
        self.style = ttk.Style(self)
        try:
            self.style.theme_use('clam')
        except Exception:
            pass
        self.repo = repo

        self.pico = None
        try:
            # Ajusta el puerto según tu entorno (usaste COM6)
            self.pico = PicoLink(port="COM6").open()
            print("[Pico] Conectado en COM6.")
        except Exception as e:
            print(f"[Pico] No conectado: {e}")

        self._show_login()

    def _show_login(self):
        for w in self.winfo_children():
            if isinstance(w, ttk.Notebook) or isinstance(w, ttk.Frame):
                w.destroy()
        LoginView(self, self.repo, on_login=self._show_main)

    def _show_main(self, user: User):
        for w in self.winfo_children():
            w.destroy()
        MainView(self, self.repo, user, pico=self.pico)

def main():
    repo = Repo(DB_PATH)
    app = App(repo)
    app.mainloop()

if __name__ == '__main__':
    main()
