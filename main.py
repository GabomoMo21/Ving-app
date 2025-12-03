#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, sqlite3, threading, socket, time, hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List, Tuple

import tkinter as tk
from tkinter import ttk, messagebox

try:
    import winsound
    def play_beep(freq=800, dur=200):
        try: winsound.Beep(freq, dur)
        except Exception: print("[beep]")
except Exception:
    def play_beep(freq=800, dur=200):
        try:
            root = tk._default_root
            if root: root.bell()
        except Exception: print("[beep]")

HAS_MPL = True
try:
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    HAS_MPL = False

# Soporte para OpenCV (cámara de la PC)
HAS_CV2 = True
try:
    import cv2
except Exception:
    HAS_CV2 = False

HAS_PYTESS = True
try:
    import pytesseract
    from pytesseract import TesseractNotFoundError

    # Intentar configurar automáticamente la ruta de tesseract en Windows
    if os.name == "nt":
        posibles_rutas = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        ]
        for ruta in posibles_rutas:
            if os.path.exists(ruta):
                pytesseract.pytesseract.tesseract_cmd = ruta
                break
except Exception:
    HAS_PYTESS = False

import re


DB_PATH = os.path.join(os.path.dirname(__file__), 'ving.db')

SCHEMA_SQL = r"""
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,failed_attempts INTEGER NOT NULL DEFAULT 0,lock_until TEXT);
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK (id = 1),remember_me INTEGER NOT NULL DEFAULT 0,remembered_email TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,alias TEXT NOT NULL,type TEXT NOT NULL,serial TEXT NOT NULL UNIQUE,location TEXT,status TEXT NOT NULL DEFAULT 'idle',armed INTEGER NOT NULL DEFAULT 0,schedules_json TEXT NOT NULL DEFAULT '[]',FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,device_id INTEGER,ts TEXT NOT NULL,type TEXT NOT NULL,severity TEXT NOT NULL,message TEXT,image_path TEXT,extra_json TEXT,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE SET NULL);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,ts TEXT NOT NULL,channel TEXT NOT NULL,priority TEXT NOT NULL,title TEXT NOT NULL,body TEXT NOT NULL,status TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS plates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plate TEXT NOT NULL,
    alias TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, plate)
);

"""

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def utcnow_str() -> str:
    return datetime.utcnow().isoformat()

def parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)

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
                cx.execute("INSERT INTO settings (id, remember_me, remembered_email, created_at) VALUES (1, 0, NULL, ?)", (utcnow_str(),))
    def create_user(self, name: str, email: str, password: str) -> int:
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            try:
                cur = cx.execute("INSERT INTO users (name, email, password_hash) VALUES (?,?,?)",(name, email, hash_password(password)))
                return cur.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("El correo ingresado ya está registrado")
    def find_user(self, email: str):
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            return cx.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    def update_user_failed_attempts(self, user_id: int, failed: int, lock_until: Optional[datetime]):
        with sqlite3.connect(self.path) as cx:
            cx.execute("UPDATE users SET failed_attempts=?, lock_until=? WHERE id=?", (failed, lock_until.isoformat() if lock_until else None, user_id))
    def set_remember_me(self, enabled: bool, email: Optional[str]):
        with sqlite3.connect(self.path) as cx:
            cx.execute("UPDATE settings SET remember_me=?, remembered_email=? WHERE id=1",(1 if enabled else 0, email))
    def get_settings(self):
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            return cx.execute("SELECT * FROM settings WHERE id=1").fetchone()
    def add_device(self, user_id: int, alias: str, type_: str, serial: str, location: str) -> int:
        with sqlite3.connect(self.path) as cx:
            try:
                cur = cx.execute("INSERT INTO devices (user_id, alias, type, serial, location) VALUES (?,?,?,?,?)",(user_id, alias, type_, serial, location))
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
            return cx.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        # NUEVO: buscar dispositivo por número de serie (para eventos que llegan en JSON)
    def find_device_by_serial(self, serial: str):
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            return cx.execute(
                "SELECT * FROM devices WHERE serial=?",
                (serial,)
            ).fetchone()

    def list_devices(self, user_id: int, q: str = '', page: int = 1, page_size: int = 10) -> Tuple[List[sqlite3.Row], int]:
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            params = [user_id]; where = "WHERE user_id=?"
            if q:
                where += " AND (alias LIKE ? OR serial LIKE ? OR type LIKE ?)"
                like = f"%{q}%"; params += [like, like, like]
            total = cx.execute(f"SELECT COUNT(*) FROM devices {where}", params).fetchone()[0]
            offset = (page - 1) * page_size
            cur = cx.execute(f"SELECT * FROM devices {where} ORDER BY alias LIMIT ? OFFSET ?", params + [page_size, offset])
            return list(cur.fetchall()), total
    def count_devices_by_type(self, user_id: int, type_: str) -> int:
        with sqlite3.connect(self.path) as cx:
            return cx.execute("SELECT COUNT(*) FROM devices WHERE user_id=? AND type=?", (user_id, type_)).fetchone()[0]
    def add_event(self, user_id: int, device_id: Optional[int], type_: str, severity: str, message: str, image_path: Optional[str], extra: dict):
        with sqlite3.connect(self.path) as cx:
            cx.execute("INSERT INTO events (user_id, device_id, ts, type, severity, message, image_path, extra_json) VALUES (?,?,?,?,?,?,?,?)",(user_id, device_id, utcnow_str(), type_, severity, message, image_path, json.dumps(extra or {})))
    def list_events(self, user_id: int, q: str = '', typ: str = '', severity: str = '', page: int = 1, page_size: int = 20, device_id: Optional[int]=None, date_from: Optional[str]=None, date_to: Optional[str]=None) -> Tuple[List[sqlite3.Row], int]:
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            wh = ["user_id=?"]; params = [user_id]
            if q: wh.append("(message LIKE ?)"); params.append(f"%{q}%")
            if typ: wh.append("type=?"); params.append(typ)
            if severity: wh.append("severity=?"); params.append(severity)
            if device_id: wh.append("device_id=?"); params.append(device_id)
            if date_from: wh.append("ts>=?"); params.append(date_from)
            if date_to: wh.append("ts<?"); params.append(date_to)
            where = " WHERE " + " AND ".join(wh)
            total = cx.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0]
            offset = (page - 1) * page_size
            cur = cx.execute(f"SELECT * FROM events{where} ORDER BY ts DESC LIMIT ? OFFSET ?", params + [page_size, offset])
            return list(cur.fetchall()), total
    def add_notification(self, user_id: int, channel: str, priority: str, title: str, body: str, status: str):
        with sqlite3.connect(self.path) as cx:
            cx.execute("INSERT INTO notifications (user_id, ts, channel, priority, title, body, status) VALUES (?,?,?,?,?,?,?)",(user_id, utcnow_str(), channel, priority, title, body, status))
        # --------- Placas autorizadas (LPR) ---------

    def add_plate(self, user_id: int, plate: str, alias: str = "") -> int:
        plate = plate.strip().upper()
        if not plate:
            raise ValueError("La placa no puede estar vacía")

        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            try:
                cur = cx.execute(
                    "INSERT INTO plates (user_id, plate, alias, created_at) "
                    "VALUES (?,?,?,?)",
                    (user_id, plate, alias, utcnow_str()
                                )
                                )
                return cur.lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("Esa placa ya está registrada")

    def list_plates(self, user_id: int):
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            cur = cx.execute(
                "SELECT * FROM plates WHERE user_id=? ORDER BY plate",
                (user_id,)
            )
            return list(cur.fetchall())

    def delete_plate(self, user_id: int, plate: str):
        plate = plate.strip().upper()
        with sqlite3.connect(self.path) as cx:
            cx.execute(
                "DELETE FROM plates WHERE user_id=? AND plate=?",
                (user_id, plate)
            )

    def find_plate(self, user_id: int, plate: str):
        plate = plate.strip().upper()
        with sqlite3.connect(self.path) as cx:
            cx.row_factory = sqlite3.Row
            return cx.execute(
                "SELECT * FROM plates WHERE user_id=? AND plate=?",
                (user_id, plate)
            ).fetchone()

    def is_plate_authorized(self, user_id: int, plate: str) -> bool:
        return self.find_plate(user_id, plate) is not None


@dataclass
class User:
    id: int
    name: str
    email: str

class Banner(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.configure(padding=8)
        self._msg = tk.StringVar(value='')
        self._lbl = ttk.Label(self, textvariable=self._msg, anchor='center', font=("Segoe UI", 10, 'bold'))
        self._lbl.pack(fill='x')
        self.hide()
    def show(self, text: str, kind: str = 'info'):
        colors = {'info':('#e8f1ff','#0b5ed7'),'success':('#e7f7ed','#0f5132'),'warning':('#fff3cd','#664d03'),'danger':('#f8d7da','#842029'),'priority':('#ffe5e5','#a80000')}
        bg, fg = colors.get(kind, colors['info'])
        self._msg.set(text)
        self._lbl.configure(background=bg, foreground=fg)
        self.pack(fill='x', side='top')
        play_beep(1000 if kind in ('danger','priority') else 700, 200)
        self.after(2500, self.hide)
    def hide(self): self.pack_forget()

class Paginator(ttk.Frame):
    def __init__(self, master, on_page, page_size=10):
        super().__init__(master); self.on_page = on_page; self.page = 1; self.total = 0; self.page_size = page_size
        self.lbl = ttk.Label(self, text=""); self.btn_prev = ttk.Button(self, text="◀", width=3, command=self.prev); self.btn_next = ttk.Button(self, text="▶", width=3, command=self.next)
        self.btn_prev.pack(side='left'); self.btn_next.pack(side='left'); self.lbl.pack(side='left', padx=8)
    def update_numbers(self, page, total):
        self.page = max(1, page); self.total = total
        pages = 1 if self.total == 0 else (self.total + self.page_size - 1)//self.page_size
        self.lbl.configure(text=f"Página {self.page} de {pages} — {self.total} registros")
        self.btn_prev['state'] = 'normal' if self.page>1 else 'disabled'
        self.btn_next['state'] = 'normal' if self.page * self.page_size < self.total else 'disabled'
    def prev(self):
        if self.page>1: self.on_page(self.page-1)
    def next(self):
        if self.page * self.page_size < self.total: self.on_page(self.page+1)

class LoginView(ttk.Frame):
    MAX_ATTEMPTS = 5
    def __init__(self, master, repo: Repo, on_login):
        super().__init__(master); self.repo = repo; self.on_login = on_login; self.pack(fill='both', expand=True)
        self.banner = Banner(self)
        frm = ttk.Frame(self, padding=20); frm.pack(expand=True)
        ttk.Label(frm, text="Ving — Inicio de sesión", font=("Segoe UI", 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=8)
        ttk.Label(frm, text="Correo").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Contraseña").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        self.ent_email = ttk.Entry(frm, width=32); self.ent_pass = ttk.Entry(frm, show='*', width=32)
        self.ent_email.grid(row=1, column=1, pady=5); self.ent_pass.grid(row=2, column=1, pady=5)
        self.var_rem = tk.BooleanVar(value=False); ttk.Checkbutton(frm, text="Mantener sesión iniciada", variable=self.var_rem).grid(row=3, column=1, sticky='w', pady=5)
        btns = ttk.Frame(frm); btns.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(btns, text="Iniciar sesión", command=self.login).pack(side='left', padx=5)
        ttk.Button(btns, text="Crear cuenta", command=self.open_register).pack(side='left', padx=5)
        st = self.repo.get_settings()
        if st and st['remember_me'] and st['remembered_email']:
            self.ent_email.insert(0, st['remembered_email']); self.var_rem.set(True)
    def open_register(self):
        RegisterDialog(self, self.repo, on_ok=lambda email: self.ent_email.delete(0,'end') or self.ent_email.insert(0,email) or self.banner.show("Registro exitoso. Ahora inicia sesión.", 'success'))
    def login(self):
        email = self.ent_email.get().strip().lower(); pw = self.ent_pass.get()
        if not email or not pw: self.banner.show("Completa correo y contraseña.", 'warning'); return
        row = self.repo.find_user(email)
        if not row: self.banner.show("Usuario o contraseña incorrectos", 'danger'); play_beep(1200, 250); return
        lock_until = parse_dt(row['lock_until']) if row['lock_until'] else None
        if lock_until and datetime.utcnow() < lock_until:
            secs = int((lock_until - datetime.utcnow()).total_seconds()); self.banner.show(f"Cuenta bloqueada. Intenta en {secs}s", 'danger'); return
        if row['password_hash'] != hash_password(pw):
            failed = row['failed_attempts'] + 1; lock = None
            if failed >= self.MAX_ATTEMPTS: lock = datetime.utcnow() + timedelta(minutes=5); failed = 0
            self.repo.update_user_failed_attempts(row['id'], failed, lock); self.banner.show("Usuario o contraseña incorrectos", 'danger'); play_beep(1200, 250); return
        self.repo.update_user_failed_attempts(row['id'], 0, None); self.repo.set_remember_me(self.var_rem.get(), email if self.var_rem.get() else None)
        user = User(id=row['id'], name=row['name'], email=row['email']); self.on_login(user)

class RegisterDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, on_ok=None):
        super().__init__(master); self.title("Crear cuenta"); self.repo = repo; self.on_ok = on_ok; self.resizable(False, False); self.grab_set()
        frm = ttk.Frame(self, padding=12); frm.pack(fill='both', expand=True)
        ttk.Label(frm, text="Nombre completo").grid(row=0, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Correo").grid(row=1, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Contraseña").grid(row=2, column=0, sticky='e', padx=5, pady=5)
        ttk.Label(frm, text="Confirmar contraseña").grid(row=3, column=0, sticky='e', padx=5, pady=5)
        self.e_name = ttk.Entry(frm, width=34); self.e_mail = ttk.Entry(frm, width=34); self.e_pw1 = ttk.Entry(frm, show='*', width=34); self.e_pw2 = ttk.Entry(frm, show='*', width=34)
        self.e_name.grid(row=0, column=1, pady=5); self.e_mail.grid(row=1, column=1, pady=5); self.e_pw1.grid(row=2, column=1, pady=5); self.e_pw2.grid(row=3, column=1, pady=5)
        ttk.Button(frm, text="Crear", command=self.create).grid(row=4, column=0, columnspan=2, pady=10)
    def create(self):
        name = self.e_name.get().strip(); email = self.e_mail.get().strip().lower(); pw1 = self.e_pw1.get(); pw2 = self.e_pw2.get()
        if not name or not email or not pw1 or not pw2: messagebox.showwarning("Campos", "Completa todos los campos"); return
        if len(pw1) < 8 or not any(c.isupper() for c in pw1) or not any(c.isdigit() for c in pw1) or not any(not c.isalnum() for c in pw1):
            messagebox.showerror("Contraseña", "La contraseña debe tener mínimo 8 caracteres, incluir una mayúscula, un número y un símbolo."); return
        if pw1 != pw2: messagebox.showerror("Contraseña", "Las contraseñas no coinciden"); return
        try: self.repo.create_user(name, email, pw1)
        except ValueError as ex: messagebox.showerror("Registro", str(ex)); return
        messagebox.showinfo("Registro", "Cuenta creada exitosamente"); 
        if self.on_ok: self.on_ok(email); 
        self.destroy()

class DevicesTab(ttk.Frame):
    TYPES = ["Detector de movimiento","Cerradura remota","Sensor de humo","Cámara con foto por movimiento","Simulador de presencia","Botón de pánico","Puertas/ventanas","Alarma silenciosa","Barrera láser","Reconocimiento de placas"]
    def __init__(self, master, repo: Repo, user: User, banner: Banner, on_event):
        super().__init__(master); self.repo=repo; self.user=user; self.banner=banner; self.on_event=on_event; self.q=''; self.page=1; self.page_size=10
        top = ttk.Frame(self); top.pack(fill='x', padx=8, pady=6)
        ttk.Label(top, text="Buscar (alias/serie/tipo):").pack(side='left')
        self.e_search = ttk.Entry(top, width=30); self.e_search.pack(side='left', padx=5)
        ttk.Button(top, text="Buscar", command=self._do_search).pack(side='left')
        ttk.Button(top, text="Limpiar", command=self._clear_search).pack(side='left', padx=5)
        ttk.Button(top, text="➕ Registrar dispositivo", command=self._open_add).pack(side='right')
        cols = ("alias","type","serial","status","location","armed")
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=12)
        for c in cols: self.tree.heading(c, text=c.capitalize()); self.tree.column(c, anchor='center', width=130)
        self.tree.pack(fill='both', expand=True, padx=8); self.tree.bind('<Double-1>', self._open_edit)
        self.pag = Paginator(self, on_page=self._goto_page, page_size=self.page_size); self.pag.pack(fill='x', padx=8, pady=4)
        act = ttk.Frame(self); act.pack(fill='x', padx=8, pady=6)
        ttk.Button(act, text="Editar alias/ubicación", command=self._open_edit).pack(side='left')
        ttk.Button(act, text="Armado/Desarmado", command=self._toggle_arm).pack(side='left', padx=6)
        ttk.Button(act, text="Configurar horarios", command=self._open_sched).pack(side='left', padx=6)
        self.refresh()
    def _do_search(self): self.q=self.e_search.get().strip(); self.page=1; self.refresh()
    def _clear_search(self): self.e_search.delete(0,'end'); self.q=''; self.page=1; self.refresh()
    def _goto_page(self, p): self.page=p; self.refresh()
    def refresh(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        rows, total = self.repo.list_devices(self.user.id, q=self.q, page=self.page, page_size=self.page_size)
        for r in rows:
            self.tree.insert('', 'end', iid=str(r['id']), values=(r['alias'], r['type'], r['serial'], r['status'], r['location'], 'Armado' if r['armed'] else 'Desarmado'))
        self.pag.update_numbers(self.page, total)
    def _selected_id(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel: self.banner.show("Selecciona un dispositivo", 'warning'); return None
        return int(sel[0])
    def _open_add(self): DeviceAddDialog(self, self.repo, self.user, on_saved=self._on_added)
    def _on_added(self):
        self.banner.show("Dispositivo registrado", 'success'); play_beep(900, 120); self.refresh()
        if self.on_event: self.on_event('devices_changed')
    def _open_edit(self, *_):
        did = self._selected_id()
        if not did: return
        DeviceEditDialog(self, self.repo, device_id=did, on_saved=lambda: (self.banner.show("Dispositivo actualizado", 'success'), self.refresh()))
    def _toggle_arm(self):
        did = self._selected_id()
        if not did:
            return

        row = self.repo.get_device(did)
        newv = not bool(row['armed'])

        self.repo.set_device_armed(did, newv)
        state = 'Armado' if newv else 'Desarmado'

        self.banner.show(f"{row['alias']}: {state}", 'info')
        self.repo.add_event(
            self.user.id,
            did,
            type_='arm_state',
            severity='low',
            message=f"Sistema {state.lower()}",
            image_path=None,
            extra={}
        )

        self.refresh()

        # 🔔 Avisar al MainView para que actualice las pestañas de tipo
        if self.on_event:
            self.on_event('devices_changed')

    def _open_sched(self):
        did = self._selected_id()
        if not did: return
        ScheduleDialog(self, self.repo, device_id=did, on_saved=lambda: self.banner.show("Horarios actualizados", 'success'))

class MotionSensorTab(ttk.Frame):
    def __init__(self, master, repo, user, banner):
        super().__init__(master)

        self.repo = repo
        self.user = user
        self.banner = banner

        ttk.Label(self, text="Eventos del sensor PIR", font=("Segoe UI", 14)).pack(pady=10)

        self.listbox = tk.Listbox(self, font=("Segoe UI", 11))
        self.listbox.pack(fill="both", expand=True, padx=10, pady=10)

        self.update_events()

    def update_events(self):
        self.listbox.delete(0, "end")
        rows, total = self.repo.list_events(self.user.id, typ="motion_start", severity="", page=1, page_size=50)

        for r in rows:
            self.listbox.insert("end", f"{r['ts']} — {r['message']}")

        self.after(2000, self.update_events)

    def refresh_state(self):
        pass


class DeviceAddDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, user: User, on_saved=None):
        super().__init__(master); self.title("Registrar dispositivo por número de serie"); self.repo=repo; self.user=user; self.on_saved=on_saved; self.resizable(False, False); self.grab_set()
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
        self.e_serial.grid(row=0, column=1, pady=6); self.cb_type.grid(row=1, column=1, pady=6); self.e_alias.grid(row=2, column=1, pady=6); self.e_loc.grid(row=3, column=1, pady=6)
        ttk.Button(frm, text="Registrar", command=self._save).grid(row=4, column=0, columnspan=2, pady=10)
    def _save(self):
        serial = self.e_serial.get().strip(); type_ = self.cb_type.get(); alias = self.e_alias.get().strip() or type_; loc = self.e_loc.get().strip()
        if not serial: messagebox.showwarning("Validación","Ingresa el número de serie"); return
        try: self.repo.add_device(self.user.id, alias, type_, serial, loc)
        except ValueError as ex: messagebox.showerror("Registro", str(ex)); return
        play_beep(900, 120); 
        if self.on_saved: self.on_saved(); 
        self.destroy()

class DeviceEditDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, device_id: int, on_saved=None):
        super().__init__(master); self.title("Editar alias y ubicación"); self.repo=repo; self.device_id=device_id; self.on_saved=on_saved; self.resizable(False, False); self.grab_set()
        row = self.repo.get_device(device_id)
        frm = ttk.Frame(self, padding=12); frm.pack(fill='both', expand=True)
        ttk.Label(frm, text="Alias").grid(row=0, column=0, sticky='e', padx=6, pady=6)
        ttk.Label(frm, text="Ubicación").grid(row=1, column=0, sticky='e', padx=6, pady=6)
        self.e_alias = ttk.Entry(frm, width=34); self.e_loc = ttk.Entry(frm, width=34)
        self.e_alias.insert(0, row['alias']); self.e_loc.insert(0, row['location'] or '')
        self.e_alias.grid(row=0, column=1, pady=6); self.e_loc.grid(row=1, column=1, pady=6)
        ttk.Button(frm, text="Guardar", command=self._save).grid(row=2, column=0, columnspan=2, pady=10)
    def _save(self):
        alias = self.e_alias.get().strip(); loc = self.e_loc.get().strip()
        if not alias: messagebox.showwarning("Validación","El alias no puede estar vacío"); return
        self.repo.edit_device(self.device_id, alias, loc)
        if self.on_saved: self.on_saved()
        self.destroy()

class ScheduleDialog(tk.Toplevel):
    def __init__(self, master, repo: Repo, device_id: int, on_saved=None):
        super().__init__(master); self.title("Programaciones de horario"); self.repo=repo; self.device_id=device_id; self.on_saved=on_saved; self.resizable(False, False); self.grab_set()
        row = self.repo.get_device(device_id); self.schedules = json.loads(row['schedules_json'] or '[]')
        frm = ttk.Frame(self, padding=12); frm.pack(fill='both', expand=True)
        ttk.Label(frm, text=f"Dispositivo: {row['alias']} — {row['type']}").pack(anchor='w')
        self.listbox = tk.Listbox(frm, width=40, height=8); self.listbox.pack(pady=6, fill='x'); self._reload_list()
        edit = ttk.Frame(frm); edit.pack(fill='x', pady=6)
        ttk.Label(edit, text="Inicio (HH:MM)").pack(side='left'); self.e_start = ttk.Entry(edit, width=7); self.e_start.pack(side='left', padx=4)
        ttk.Label(edit, text="Fin (HH:MM)").pack(side='left'); self.e_end = ttk.Entry(edit, width=7); self.e_end.pack(side='left', padx=4)
        ttk.Button(edit, text="Agregar", command=self._add).pack(side='left', padx=6); ttk.Button(edit, text="Eliminar", command=self._del).pack(side='left')
        ttk.Button(frm, text="Guardar", command=self._save).pack(pady=8)
    def _reload_list(self):
        self.listbox.delete(0,'end')
        for it in self.schedules: self.listbox.insert('end', f"{it['start']} - {it['end']}")
    @staticmethod
    def _valid_hhmm(s: str) -> bool:
        try: datetime.strptime(s, '%H:%M'); return True
        except Exception: return False
    def _conflicts(self, news: List[dict]) -> Optional[Tuple[int,int]]:
        def to_min(x): h,m = map(int, x.split(':')); return h*60+m
        ranges = [(to_min(i['start']), to_min(i['end'])) for i in news]; ranges.sort()
        for i in range(1, len(ranges)):
            if ranges[i][0] < ranges[i-1][1]: return ranges[i-1], ranges[i]
        return None
    def _add(self):
        s = self.e_start.get().strip(); e = self.e_end.get().strip()
        if not (self._valid_hhmm(s) and self._valid_hhmm(e)): messagebox.showerror("Hora", "Usa formato HH:MM"); return
        if s >= e: messagebox.showerror("Rango", "El inicio debe ser menor que el fin"); return
        tmp = self.schedules + [{"start":s, "end":e}]
        c = self._conflicts(tmp)
        if c: messagebox.showerror("Conflicto", "Existe un solapamiento entre horarios definidos"); return
        self.schedules.append({"start":s, "end":e}); self._reload_list()
    def _del(self):
        sel = self.listbox.curselection()
        if not sel: return
        self.schedules.pop(sel[0]); self._reload_list()
    def _save(self):
        self.repo.set_device_schedules(self.device_id, json.dumps(self.schedules))
        if self.on_saved: self.on_saved()
        self.destroy()

class EventsTab(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master); self.repo=repo; self.user=user; self.banner=banner; self.q=''; self.page=1; self.page_size=20
        filt = ttk.Frame(self); filt.pack(fill='x', padx=8, pady=6)
        ttk.Label(filt, text="Buscar").pack(side='left'); self.e_q = ttk.Entry(filt, width=24); self.e_q.pack(side='left', padx=5)
        ttk.Label(filt, text="Tipo").pack(side='left', padx=(12,4)); self.e_type = ttk.Entry(filt, width=16); self.e_type.pack(side='left')
        ttk.Label(filt, text="Severidad").pack(side='left', padx=(12,4)); self.e_sev = ttk.Combobox(filt, values=['','low','medium','high','critical'], width=10, state='readonly'); self.e_sev.current(0); self.e_sev.pack(side='left')
        ttk.Button(filt, text="Filtrar", command=self._do_filter).pack(side='left', padx=6); ttk.Button(filt, text="Limpiar", command=self._clear).pack(side='left')
        cols = ("ts","type","severity","device","location","message")
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=14)
        for c, w in zip(cols, (160,120,100,160,120,400)):
            self.tree.heading(c, text=c.capitalize()); self.tree.column(c, width=w, anchor='center' if c!="message" else 'w')
        self.tree.pack(fill='both', expand=True, padx=8); self.tree.bind('<ButtonRelease-1>', lambda *_: None)
        self.pag = Paginator(self, on_page=self._goto, page_size=self.page_size); self.pag.pack(fill='x', padx=8, pady=6)
        ttk.Frame(self).pack_forget()
        self.refresh()
    def _do_filter(self): self.q=self.e_q.get().strip(); self.page=1; self.refresh()
    def _clear(self): self.e_q.delete(0,'end'); self.e_type.delete(0,'end'); self.e_sev.current(0); self.q=''; self.page=1; self.refresh()
    def _goto(self, p): self.page=p; self.refresh()
    def refresh(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        rows, total = self.repo.list_events(self.user.id, q=self.q, typ=self.e_type.get().strip(), severity=self.e_sev.get().strip(), page=self.page, page_size=self.page_size)
        for r in rows:
            device = ''; location = ''
            if r['device_id']:
                d = self.repo.get_device(r['device_id'])
                if d: device = d['alias']; location = d['location'] or ''
            iid = str(r['id'])
            self.tree.insert('', 'end', iid=iid, values=(r['ts'], r['type'], r['severity'], device, location, r['message']))
            if r['severity'] in ('high','critical'):
                self.tree.tag_configure('critical', background='#ffe5e5'); self.tree.item(iid, tags=('critical',))
        self.pag.update_numbers(self.page, total)

class HistogramTab(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master); self.repo=repo; self.user=user; self.banner=banner
        ctr = ttk.Frame(self); ctr.pack(fill='x', padx=8, pady=6)
        ttk.Label(ctr, text="Dispositivo (opcional ID)").pack(side='left'); self.e_dev = ttk.Entry(ctr, width=8); self.e_dev.pack(side='left', padx=4)
        ttk.Label(ctr, text="Desde (YYYY-MM-DD)").pack(side='left', padx=(10,4)); self.e_from = ttk.Entry(ctr, width=12); self.e_from.pack(side='left')
        ttk.Label(ctr, text="Hasta (YYYY-MM-DD)").pack(side='left', padx=(10,4)); self.e_to = ttk.Entry(ctr, width=12); self.e_to.pack(side='left')
        ttk.Button(ctr, text="Generar", command=self._plot).pack(side='left', padx=6)
        self.canvas = None
        if not HAS_MPL: ttk.Label(self, text="Instala matplotlib para ver el histograma.").pack(pady=12)
    def _plot(self):
        if not HAS_MPL:
            try:
                from matplotlib.figure import Figure
                from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            except Exception as e:
                self.banner.show(f"matplotlib no disponible: {e.__class__.__name__}", 'warning'); return
        device_id = int(self.e_dev.get()) if self.e_dev.get().strip().isdigit() else None
        date_from = self.e_from.get().strip() or None; date_to = self.e_to.get().strip() or None
        rows, _ = self.repo.list_events(self.user.id, page=1, page_size=10000, device_id=device_id, date_from=date_from, date_to=date_to)
        counts = {}; days = []
        if date_from and date_to:
            try:
                d0 = datetime.fromisoformat(date_from); d1 = datetime.fromisoformat(date_to); cur = d0
                while cur <= d1:
                    key = cur.strftime('%Y-%m-%d'); counts[key] = 0; days.append(key); cur += timedelta(days=1)
            except Exception: pass
        for r in rows:
            key = r['ts'][:10]; counts[key] = counts.get(key, 0) + 1
            if key not in days: days.append(key)
        days.sort(); vals = [counts.get(d,0) for d in days]
        fig = Figure(figsize=(7,3), dpi=100); ax = fig.add_subplot(111)
        ax.bar(days, vals); ax.set_title('Eventos por día'); ax.set_ylabel('# eventos'); ax.set_xticklabels(days, rotation=30, ha='right')
        if self.canvas: self.canvas.get_tk_widget().destroy()
        self.canvas = FigureCanvasTkAgg(fig, master=self); self.canvas.draw(); self.canvas.get_tk_widget().pack(fill='both', expand=True, padx=8, pady=8)

class WiFiPicoBridge:
    def __init__(self, host="0.0.0.0", port=12345, repo: Optional[Repo] = None):
        self.host = host
        self.port = port
        self.repo = repo             # <- acceso directo al Repo para guardar eventos
        self._srv = None
        self._thr = None
        self._pico = None
        self._lock = threading.Lock()
        self._start_server()

    def _start_server(self):
        def loop():
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(5)
            self._srv = srv
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

                # Conexión de control de la Pico (cerradura / servo)
                if b"PICO_READY" in first:
                    with self._lock:
                        if self._pico:
                            try:
                                self._pico.close()
                            except Exception:
                                pass
                        self._pico = c
                else:
                    # Cualquier otro cliente: lo manejamos en un hilo aparte
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(c, first),
                        daemon=True
                    )
                    t.start()

        self._thr = threading.Thread(target=loop, daemon=True)
        self._thr.start()

    def _handle_client(self, sock, prefeed: bytes):
        """Maneja conexiones "normales": JSON de eventos o comandos de texto."""
        try:
            buf = prefeed or b""
            while True:
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    # Si no llega nada un rato, cerramos
                    break
                except Exception:
                    break

                if not data:
                    break
                buf += data

                # Procesar línea por línea (\n o \r)
                while b"\n" in buf or b"\r" in buf:
                    if b"\n" in buf:
                        idx = buf.index(b"\n")
                    else:
                        idx = buf.index(b"\r")

                    line_bytes = buf[:idx]
                    buf = buf[idx + 1:]

                    line = line_bytes.decode("utf-8", "ignore").strip()
                    if not line:
                        continue

                    # 1) Intentar tratarlo como JSON de evento
                    if self._try_handle_json_event(line):
                        # Puedes mandar un ACK simple si quieres
                        try:
                            sock.sendall(b"OK\n")
                        except Exception:
                            pass
                        continue

                    # 2) Si no es JSON válido de evento, lo tratamos como comando de texto
                    resp = self.send_line(line)
                    try:
                        sock.sendall((resp + "\n").encode("utf-8"))
                    except Exception:
                        pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _try_handle_json_event(self, line: str) -> bool:
        """
        Intenta interpretar la línea como un JSON de evento de dispositivo.
        Devuelve True si se procesó como evento (aunque el dispositivo no exista),
        False si no era un JSON de evento y hay que tratarlo como comando normal.
        """
        if not self.repo:
            return False

        try:
            obj = json.loads(line)
        except Exception:
            return False

        if not isinstance(obj, dict):
            return False

        # Opcional: campo "kind": "event" para dejar claro que es un evento
        kind = obj.get("kind") or obj.get("type_kind") or ""
        if kind and kind not in ("event", "hw_event"):
            # Si trae "kind" pero no es de tipo evento, no lo tocamos
            return False

        # Número de serie del dispositivo (debe coincidir con devices.serial en la BD)
        serial = obj.get("serial") or obj.get("device_serial")
        if not serial:
            return False

        row = self.repo.find_device_by_serial(serial)
        if not row:
            # El JSON es válido, pero el dispositivo no existe en la app
            print(f"[WiFiPicoBridge] Evento para serie desconocida: {serial}")
            return True  # lo consideramos manejado para no enviar error al cliente

        
        if not bool(row["armed"]):
            print(f"[WiFiPicoBridge] Evento ignorado (dispositivo DESARMADO): {serial}")
            return True  # No guardamos nada en la bitácora

        user_id = row["user_id"]
        device_id = row["id"]

        # Campos de evento
        event_type = obj.get("event_type") or obj.get("type") or "generic"
        severity = obj.get("severity") or "low"
        message = (
            obj.get("message")
            or obj.get("msg")
            or f"Evento {event_type} desde dispositivo {serial}"
        )


        extra = obj.get("extra") or {}
        if not isinstance(extra, dict):
            extra = {"value": extra}
        # Marcamos fuente como hardware / WiFi
        extra.setdefault("source", "wifi")

        # Guardar en la bitácora (tabla events)
        self.repo.add_event(
            user_id=user_id,
            device_id=device_id,
            type_=event_type,
            severity=severity,
            message=message,
            image_path=None,
            extra=extra,
        )

        print(f"[WiFiPicoBridge] Evento registrado: {event_type} ({severity}) serial={serial}")
        return True

    def _readline(self, s, timeout_ms=1500):
        """Lectura bloqueante de una línea de la Pico (para respuestas a comandos)."""
        s.settimeout(0.05)
        buf = b""
        t0 = time.time()
        while (time.time() - t0) * 1000 < timeout_ms:
            try:
                ch = s.recv(1)
            except socket.timeout:
                continue
            except Exception:
                break
            if not ch:
                break
            buf += ch
            if buf.endswith(b"\n") or buf.endswith(b"\r"):
                break
        return buf.decode("utf-8", "ignore").strip()

    def send_line(self, line: str) -> str:
        """
        Comandos hacia la Pico (cerradura / servo).
        Mantiene el comportamiento original: ping, open, close, servo...
        """
        cmd = line.strip().lower()
        if cmd == "ping":
            cmd_out = "PING"
        elif cmd == "open":
            cmd_out = "LOCK OPEN"
        elif cmd == "close":
            cmd_out = "LOCK CLOSE"
        elif cmd.startswith("servo"):
            parts = cmd.split()
            if len(parts) == 2:
                try:
                    ang = int(float(parts[1]))
                    ang = max(0, min(180, ang))
                    cmd_out = f"SERVO {ang}"
                except Exception:
                    return "ERR BAD ANGLE"
            else:
                return "ERR BAD ANGLE"
        else:
            cmd_out = line.strip()

        with self._lock:
            if not self._pico:
                return "ERR NO_PICO"
            try:
                self._pico.sendall((cmd_out + "\n").encode("utf-8"))
                resp = self._readline(self._pico, timeout_ms=2000)
                return resp if resp else "ERR NO_RESP"
            except Exception:
                try:
                    self._pico.close()
                except Exception:
                    pass
                self._pico = None
                return "ERR SEND"

    def is_connected(self) -> bool:
        with self._lock:
            return self._pico is not None


class UsbPicoLink:
    def __init__(self, port="5", baud=115200):
        self.port=port; self.baud=baud; self.ser=None
    def open(self):
        try:
            import serial, serial.tools.list_ports
        except Exception:
            return None
        try:
            self.ser = serial.Serial(self.port, self.baud, timeout=1)
            time.sleep(0.2)
            return self
        except Exception:
            return None
    def _readline(self, timeout=1.5):
        t0=time.time(); buf=b""
        while (time.time()-t0)<timeout:
            b = self.ser.read(1)
            if not b: continue
            buf += b
            if buf.endswith(b"\n") or buf.endswith(b"\r"): break
        return buf.decode("utf-8","ignore").strip()
    def send_line(self, line:str)->str:
        try:
            self.ser.write((line.strip()+"\n").encode("utf-8"))
            return self._readline(2.0) or "ERR NO_RESP"
        except Exception:
            return "ERR SEND"
    def is_connected(self)->bool:
        return self.ser is not None and self.ser.is_open

class PicoUnified:
    def __init__(self, wifi: WiFiPicoBridge, usb: Optional[UsbPicoLink]):
        self.wifi = wifi; self.usb = usb
    def _send(self, cmd:str)->str:
        if self.wifi and self.wifi.is_connected(): return self.wifi.send_line(cmd)
        if self.usb and self.usb.is_connected(): return self.usb.send_line(cmd)
        return "ERR NO_PICO"
    def ping(self)->bool: return self._send("PING")=="PONG"
    def lock_open(self)->bool: return "OK LOCK OPEN" in self._send("LOCK OPEN")
    def lock_close(self)->bool: return "OK LOCK CLOSE" in self._send("LOCK CLOSE")
    def servo(self, ang:int)->bool: return "OK SERVO" in self._send(f"SERVO {ang}")

    def send_line(self, line: str) -> str:
        """
        Enviar un comando arbitrario a la Pico.
        Mantiene la lógica unificada: primero WiFi, luego USB (COM).
        """
        return self._send(line)

class LockTab(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, banner: Banner, pico:PicoUnified):
        super().__init__(master); self.repo=repo; self.user=user; self.banner=banner; self.pico=pico
        info = ttk.Frame(self, padding=10); info.pack(fill='x')
        ttk.Label(info, text="Control de cerradura (0° abrir, 90° cerrar)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        btns = ttk.Frame(self, padding=10); btns.pack(fill='x')
        self.btn_open = ttk.Button(btns, text="Abrir", command=self._open_hw)
        self.btn_close = ttk.Button(btns, text="Cerrar", command=self._close_hw)
        self.btn_open.pack(side="left", padx=6, pady=6); self.btn_close.pack(side="left", padx=6, pady=6)
        self.state_lbl = ttk.Label(self, text="Estado: —", padding=10); self.state_lbl.pack(anchor="w")
        self.refresh_state()
    def _device_count(self) -> int:
        return self.repo.count_devices_by_type(self.user.id, "Cerradura remota")
    def refresh_state(self):
        cnt = self._device_count()
        if cnt <= 0:
            self.state_lbl.config(text="Necesitas añadir un dispositivo de este tipo")
            self.btn_open.configure(state='disabled'); self.btn_close.configure(state='disabled')
        else:
            if self.state_lbl.cget("text").startswith("Necesitas añadir"): self.state_lbl.config(text="Estado: —")
            self.btn_open.configure(state='normal'); self.btn_close.configure(state='normal')
    def _pick_device(self) -> Optional[int]:
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            r = cx.execute("SELECT id FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",(self.user.id,"Cerradura remota")).fetchone()
            return r['id'] if r else None
    def _open_hw(self):
        ok = self.pico.lock_open()
        if not ok: self.banner.show("No se pudo abrir la cerradura", 'danger'); return
        did = self._pick_device()
        if did: self.repo.set_device_status(did, 'unlocked')
        self.repo.add_event(self.user.id, did, 'lock', 'low', "Cerradura unlocked [HW]", None, {"by":"desktop"})
        self.banner.show("Cerradura abierta (0°)", 'success'); self.state_lbl.config(text="Estado: abierta (0°)"); play_beep(880, 140)
    def _close_hw(self):
        ok = self.pico.lock_close()
        if not ok: self.banner.show("No se pudo cerrar la cerradura", 'danger'); return
        did = self._pick_device()
        if did: self.repo.set_device_status(did, 'locked')
        self.repo.add_event(self.user.id, did, 'lock', 'low', "Cerradura locked [HW]", None, {"by":"desktop"})
        self.banner.show("Cerradura cerrada (90°)", 'success'); self.state_lbl.config(text="Estado: cerrada (90°)"); play_beep(740, 140)

class LprTab(ttk.Frame):
    """
    Pestaña específica para reconocimiento de placas (LPR) con cámara de la PC.
    - Permite registrar placas autorizadas.
    - Usa la cámara para leer la placa (OCR con Tesseract).
    - Genera eventos y alertas si la placa NO está registrada.
    """
    DEVICE_TYPE = "Reconocimiento de placas"

    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master)
        self.repo = repo
        self.user = user
        self.banner = banner

        self._cam_thread = None
        self._stop_flag = False
        self._last_detection_time = 0.0

        # ----- Info general -----
        info = ttk.Frame(self, padding=10)
        info.pack(fill="x")
        ttk.Label(
            info,
            text="Panel específico — Reconocimiento de placas (cámara PC + OCR)",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        if not HAS_CV2 or not HAS_PYTESS:
            msg = "Requiere OpenCV y pytesseract instalados."
            ttk.Label(info, text=msg, foreground="red").pack(anchor="w")

        # ----- Placas autorizadas -----
        frm_auth = ttk.LabelFrame(self, text="Placas autorizadas", padding=10)
        frm_auth.pack(fill="x", padx=10, pady=5)

        ttk.Label(frm_auth, text="Placa:").grid(row=0, column=0, padx=4, pady=4, sticky="e")
        self.e_plate_auth = ttk.Entry(frm_auth, width=12)
        self.e_plate_auth.grid(row=0, column=1, padx=4, pady=4)

        ttk.Label(frm_auth, text="Alias (opcional):").grid(row=0, column=2, padx=4, pady=4, sticky="e")
        self.e_alias_auth = ttk.Entry(frm_auth, width=20)
        self.e_alias_auth.grid(row=0, column=3, padx=4, pady=4)

        ttk.Button(
            frm_auth,
            text="Agregar placa autorizada",
            command=self._add_plate
        ).grid(row=0, column=4, padx=6, pady=4)

        self.list_auth = tk.Listbox(frm_auth, height=6)
        self.list_auth.grid(row=1, column=0, columnspan=4, sticky="nsew", padx=4, pady=4)

        ttk.Button(
            frm_auth,
            text="Eliminar seleccionada",
            command=self._del_plate
        ).grid(row=1, column=4, padx=6, pady=4, sticky="n")

        frm_auth.columnconfigure(3, weight=1)
        frm_auth.rowconfigure(1, weight=1)

        # ----- Cámara LPR -----
        frm_cam = ttk.LabelFrame(self, text="Cámara LPR (PC)", padding=10)
        frm_cam.pack(fill="x", padx=10, pady=5)

        self.lbl_devices = ttk.Label(frm_cam, text="")
        self.lbl_devices.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))

        self.btn_start = ttk.Button(
            frm_cam,
            text="Iniciar cámara LPR",
            command=self._start_camera
        )
        self.btn_start.grid(row=1, column=0, padx=4, pady=4)

        self.btn_stop = ttk.Button(
            frm_cam,
            text="Detener cámara LPR",
            command=self._stop_camera,
            state="disabled"
        )
        self.btn_stop.grid(row=1, column=1, padx=4, pady=4)

        self.lbl_result = ttk.Label(frm_cam, text="No hay lecturas todavía.", padding=8)
        self.lbl_result.grid(row=2, column=0, columnspan=3, sticky="w")

        # Cargar datos iniciales
        self._reload_auth()
        self.refresh_state()

    # ---------- Gestión de placas autorizadas ----------

    def _reload_auth(self):
        self.list_auth.delete(0, "end")
        rows = self.repo.list_plates(self.user.id)
        for r in rows:
            alias = r["alias"] or ""
            txt = r["plate"] if not alias else f"{r['plate']} — {alias}"
            self.list_auth.insert("end", txt)

    def _add_plate(self):
        plate = self.e_plate_auth.get().strip().upper()
        alias = self.e_alias_auth.get().strip()
        if not plate:
            self.banner.show("Ingresa una placa para registrar", "warning")
            return
        try:
            self.repo.add_plate(self.user.id, plate, alias)
        except ValueError as ex:
            self.banner.show(str(ex), "danger")
            return
        self.e_plate_auth.delete(0, "end")
        self.e_alias_auth.delete(0, "end")
        self._reload_auth()
        self.banner.show(f"Placa {plate} registrada como autorizada", "success")

    def _del_plate(self):
        sel = self.list_auth.curselection()
        if not sel:
            return
        txt = self.list_auth.get(sel[0])
        plate = txt.split("—")[0].strip().upper()
        self.repo.delete_plate(self.user.id, plate)
        self._reload_auth()
        self.banner.show(f"Placa {plate} eliminada de autorizadas", "info")

    # ---------- Utilidades de dispositivos ----------

    def _device_count(self) -> int:
        return self.repo.count_devices_by_type(self.user.id, self.DEVICE_TYPE)

    def _pick_device(self) -> Optional[int]:
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            r = cx.execute(
                "SELECT id FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",
                (self.user.id, self.DEVICE_TYPE)
            ).fetchone()
            return r["id"] if r else None

    # ---------- API llamada desde MainView ----------

    def refresh_state(self):
        cnt = self._device_count()
        if cnt <= 0:
            self.lbl_devices.configure(
                text="No hay dispositivo de tipo 'Reconocimiento de placas'. "
                     "Registra uno en la pestaña Dispositivos.",
                foreground="gray"
            )
        else:
            self.lbl_devices.configure(
                text=f"Hay {cnt} dispositivo(s) de tipo '{self.DEVICE_TYPE}'.",
                foreground="black"
            )

    # ---------- Cámara LPR ----------

    def _start_camera(self):
        if not HAS_CV2 or not HAS_PYTESS:
            self.banner.show("Falta OpenCV o pytesseract para usar la cámara LPR", "danger")
            return
        if self._cam_thread and self._cam_thread.is_alive():
            return
        self._stop_flag = False
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        t = threading.Thread(target=self._camera_loop, daemon=True)
        self._cam_thread = t
        t.start()
        self.banner.show("Cámara LPR iniciada (ventana de OpenCV).", "info")

    def _stop_camera(self):
        self._stop_flag = True
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.banner.show("Cámara LPR detenida.", "info")

    def _camera_loop(self):
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            self._update_result("No se pudo abrir la cámara de la PC.")
            self._stop_camera()
            return

        COOLDOWN = 5.0  # segundos entre detecciones
        regex_plate = re.compile(r"[A-Z0-9]{5,8}")

        while not self._stop_flag:
            ret, frame = cap.read()
            if not ret:
                break

            # Mostrar la imagen en una ventana aparte
            cv2.imshow("LPR - Cámara PC", frame)
            if cv2.waitKey(30) & 0xFF == 27:  # ESC para cerrar manualmente
                self._stop_flag = True
                break

            # Región central donde esperamos la placa (simulación)
            h, w, _ = frame.shape
            y1, y2 = int(h * 0.4), int(h * 0.7)
            x1, x2 = int(w * 0.2), int(w * 0.8)
            roi = frame[y1:y2, x1:x2]

            gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 120, 255, cv2.THRESH_BINARY)

            # ----- OCR con manejo de errores -----
            try:
                text_raw = pytesseract.image_to_string(
                    thresh,
                    config="--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                )
            except TesseractNotFoundError:
                # Error típico: tesseract no instalado o no en PATH
                self._update_result("Error: Tesseract no está instalado o no está en el PATH.")
                self.banner.show("Error de Tesseract: verifica la instalación y la ruta.", "danger")
                self._stop_flag = True
                break
            except Exception as e:
                # Cualquier otro error de OCR: lo mostramos pero no crasheamos
                self._update_result(f"Error de OCR: {e}")
                # Continuamos con el siguiente frame
                continue

            text_raw = text_raw.strip().upper().replace(" ", "")

            match = regex_plate.search(text_raw)
            if match:
                plate = match.group(0)
                now = time.time()
                if now - self._last_detection_time > COOLDOWN:
                    self._handle_plate_detected(plate)
                    self._last_detection_time = now

        cap.release()
        # Destruir la ventana de forma segura (puede no existir)
        try:
            cv2.destroyWindow("LPR - Cámara PC")
        except Exception:
            try:
                cv2.destroyAllWindows()
            except Exception:
                pass

    def _update_result(self, text: str):
        self.after(0, lambda: self.lbl_result.configure(text=text))

    def _handle_plate_detected(self, plate: str):
        autorizado = self.repo.is_plate_authorized(self.user.id, plate)
        did = self._pick_device()

        msg = (
            f"Placa {plate} autorizada"
            if autorizado
            else f"Placa {plate} NO autorizada"
        )
        severity = "low" if autorizado else "high"

        self.repo.add_event(
            self.user.id,
            did,
            type_="lpr",
            severity=severity,
            message=msg,
            image_path=None,
            extra={"plate": plate, "authorized": autorizado, "source": "desktop_lpr_cam"}
        )

        if not autorizado:
            self.repo.add_notification(
                self.user.id,
                channel="inapp",
                priority="alta",
                title="LPR",
                body=f"Vehículo NO registrado ({plate})",
                status="sent"
            )
            self.banner.show(msg, "priority")
        else:
            self.banner.show(msg, "info")

        self._update_result(msg)


class DeviceTypeTab(ttk.Frame):
    def __init__(
        self,
        master,
        repo: Repo,
        user: User,
        banner: Banner,
        device_type: str,
        title: str,
        require_device: bool = True   # ← NUEVO
    ):
        super().__init__(master)
        self.repo = repo
        self.user = user
        self.banner = banner
        self.device_type = device_type
        self.require_device = require_device  # ← NUEVO

        info = ttk.Frame(self, padding=10)
        info.pack(fill='x')
        ttk.Label(info, text=title, font=("Segoe UI", 10, "bold")).pack(anchor='w')

        self.msg_lbl = ttk.Label(self, text="", padding=10)
        self.msg_lbl.pack(anchor='w')

        self.btn_frame = ttk.Frame(self, padding=10)
        self.btn_frame.pack(fill='x')

        self.btn_action = ttk.Button(
            self.btn_frame,
            text="Simular evento",
            command=self._simulate
        )
        self.btn_action.pack(side='left', padx=4, pady=4)

        self.refresh_state()
    def _device_count(self) -> int: return self.repo.count_devices_by_type(self.user.id, self.device_type)
    def refresh_state(self):
        cnt = self._device_count()

        # Caso normal: sí requiere dispositivo registrado
        if self.require_device:
            if cnt <= 0:
                self.msg_lbl.configure(
                    text="Necesitas añadir un dispositivo de este tipo",
                    foreground='gray'
                )
                for c in self.btn_frame.winfo_children():
                    c.configure(state='disabled')
            else:
                self.msg_lbl.configure(
                    text=f"Hay {cnt} dispositivo(s) de tipo {self.device_type}.",
                    foreground='black'
                )
                for c in self.btn_frame.winfo_children():
                    c.configure(state='normal')
        # Caso especial: NO requiere dispositivo (pánico)
        else:
            if cnt <= 0:
                # No hay dispositivo, pero el botón igual funciona
                self.msg_lbl.configure(
                    text=f"Botón activo (sin dispositivo registrado)",
                    foreground='black'
                )
            else:
                self.msg_lbl.configure(
                    text=f"Hay {cnt} dispositivo(s) de tipo {self.device_type}.",
                    foreground='black'
                )
            # Siempre habilitado
            for c in self.btn_frame.winfo_children():
                c.configure(state='normal')
    def _simulate(self):
        did = None
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            r = cx.execute("SELECT id FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",(self.user.id, self.device_type)).fetchone()
            if r: did = r['id']
        self.repo.add_event(self.user.id, did, 'generic', 'low', f"Evento simulado para tipo {self.device_type}", None, {})
        self.banner.show(f"Evento simulado ({self.device_type})", 'info'); play_beep(900, 120)

class CameraTab(ttk.Frame):
    """
    Pestaña específica para 'Cámara con foto por movimiento'.
    - Solo se activa si hay al menos una cámara registrada y ARMADA.
    - Usa la cámara de la PC (cv2.VideoCapture(0)).
    - Cuando detecta movimiento, guarda foto y registra evento en la bitácora.
    """
    DEVICE_TYPE = "Cámara con foto por movimiento"

    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master)
        self.repo = repo
        self.user = user
        self.banner = banner

        self._cam_thread = None
        self._stop_flag = False

        info = ttk.Frame(self, padding=10)
        info.pack(fill="x")
        ttk.Label(
            info,
            text="Panel específico — Cámara con foto por movimiento",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        self.lbl_status = ttk.Label(self, text="", padding=10)
        self.lbl_status.pack(anchor="w")

        if not HAS_CV2:
            self._set_status(
                "OpenCV no está disponible. Instala con: "
                "python -m pip install opencv-python"
            )
        else:
            self._set_status(
                "Esperando que registres una cámara y la marques como Armado."
            )

        # Para que MainView pueda llamarlo en _refresh_type_tabs
        self.refresh_state()

    # ---------- utilidades internas ----------

    def _set_status(self, text: str):
        # Aseguramos modificar el label desde el hilo de Tkinter
        self.after(0, lambda: self.lbl_status.config(text=text))

    def _has_armed_camera(self) -> bool:
        """¿Hay al menos una cámara de este tipo armada para este usuario?"""
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            r = cx.execute(
                "SELECT 1 FROM devices "
                "WHERE user_id=? AND type=? AND armed=1 "
                "LIMIT 1",
                (self.user.id, self.DEVICE_TYPE)
            ).fetchone()
            return bool(r)

    def _get_first_armed_camera_id(self) -> Optional[int]:
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            r = cx.execute(
                "SELECT id FROM devices "
                "WHERE user_id=? AND type=? AND armed=1 "
                "ORDER BY id LIMIT 1",
                (self.user.id, self.DEVICE_TYPE)
            ).fetchone()
            return r["id"] if r else None

    # ---------- API llamada desde MainView ----------

    def refresh_state(self):
        """
        Llamado cuando cambian los dispositivos (armado/desarmado).
        Arranca o detiene el hilo de la cámara según corresponda.
        """
        if not HAS_CV2:
            # Si no hay OpenCV, no hacemos nada más
            return

        if self._has_armed_camera():
            self._start_watcher()
            self._set_status(
                "Cámara armada: detección de movimiento activa "
                "(usando la cámara de la PC)."
            )
        else:
            self._stop_watcher()
            self._set_status(
                "No hay cámara armada.\n"
                "Registra un dispositivo de tipo "
                "'Cámara con foto por movimiento' y márcalo como Armado."
            )

    # ---------- manejo del hilo de vigilancia ----------

    def _start_watcher(self):
        if self._cam_thread and self._cam_thread.is_alive():
            return  # ya está corriendo
        self._stop_flag = False
        t = threading.Thread(target=self._camera_loop, daemon=True)
        self._cam_thread = t
        t.start()

    def _stop_watcher(self):
        self._stop_flag = True

    # ---------- bucle principal de la cámara ----------

    def _camera_loop(self):
        """
        Bucle de vigilancia:
        - Abre la cámara de la PC.
        - Compara frames consecutivos.
        - Si hay mucho cambio, asume movimiento, guarda foto y registra evento.
        """
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            self._set_status("No se pudo abrir la cámara de la PC.")
            return

        ret, frame_prev = cap.read()
        if not ret:
            self._set_status("No se pudo leer el primer fotograma de la cámara.")
            cap.release()
            return

        frame_prev_gray = cv2.cvtColor(frame_prev, cv2.COLOR_BGR2GRAY)
        frame_prev_gray = cv2.GaussianBlur(frame_prev_gray, (21, 21), 0)

        MOTION_THRESHOLD = 5000      # píxeles "diferentes" para considerar movimiento
        COOLDOWN_SECONDS = 3.0       # tiempo mínimo entre fotos
        last_capture_time = 0.0

        while not self._stop_flag:
            ret, frame = cap.read()
            if not ret:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.GaussianBlur(gray, (21, 21), 0)

            frame_delta = cv2.absdiff(frame_prev_gray, gray)
            _, thresh = cv2.threshold(frame_delta, 25, 255, cv2.THRESH_BINARY)
            motion_pixels = cv2.countNonZero(thresh)

            if motion_pixels > MOTION_THRESHOLD:
                now = time.time()
                if now - last_capture_time > COOLDOWN_SECONDS:
                    did = self._get_first_armed_camera_id()
                    if did is None:
                        # Ya no hay cámara armada, salimos del bucle
                        self._set_status(
                            "No hay cámara armada, deteniendo vigilancia."
                        )
                        break

                    # Carpeta donde se guardan las fotos
                    captures_dir = os.path.join(
                        os.path.dirname(__file__), "capturas_pc_cam"
                    )
                    os.makedirs(captures_dir, exist_ok=True)

                    filename = time.strftime("cam_%Y%m%d_%H%M%S.jpg")
                    full_path = os.path.join(captures_dir, filename)

                    try:
                        cv2.imwrite(full_path, frame)
                    except Exception:
                        # Si falla, no queremos romper el hilo
                        pass

                    msg = f"Movimiento detectado en cámara. Foto: {filename}"

                    # Registrar en bitácora
                    self.repo.add_event(
                        self.user.id,
                        did,
                        type_="camera_motion",
                        severity="high",
                        message=msg,
                        image_path=full_path,
                        extra={"source": "pc_camera"}
                    )

                    # Notificación en la app
                    self.repo.add_notification(
                        self.user.id,
                        channel="inapp",
                        priority="alta",
                        title="Movimiento en cámara",
                        body=msg,
                        status="sent"
                    )

                    # Mostrar algo en la pestaña
                    self._set_status(f"Última captura: {filename}")

                    last_capture_time = now

            frame_prev_gray = gray
            time.sleep(0.1)

        cap.release()



class PresenceSimTab(ttk.Frame):
    """
    Pestaña de simulador de presencia.
    Replica la interfaz de SimuladorGUI pero integrada en VING
    y usando PicoUnified (WiFi/USB) en lugar de abrir su propio Serial.
    """
    def __init__(self, master, repo: Repo, user: User, banner: Banner, pico: PicoUnified):
        super().__init__(master)
        self.repo = repo
        self.user = user
        self.banner = banner
        self.pico = pico

        # ---- Construcción de la interfaz ----
        self._crear_widgets()

    # -------------------------------------------------
    # Construye todos los widgets de la interfaz
    # -------------------------------------------------
    def _crear_widgets(self):
        # Título
        info = ttk.Frame(self, padding=10)
        info.pack(fill="x")
        ttk.Label(
            info,
            text="Simulador de presencia (horarios y control manual)",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        # Hora actual
        ttk.Label(self, text="Hora actual").pack(pady=(5, 0))

        frame_now = ttk.Frame(self)
        frame_now.pack(pady=5)

        ttk.Label(frame_now, text="Hora:").grid(row=0, column=0, padx=2)
        self.entryHourNow = ttk.Entry(frame_now, width=3)
        self.entryHourNow.grid(row=0, column=1, padx=2)

        ttk.Label(frame_now, text="Minuto:").grid(row=0, column=2, padx=2)
        self.entryMinuteNow = ttk.Entry(frame_now, width=3)
        self.entryMinuteNow.grid(row=0, column=3, padx=2)

        # Hora de encendido
        ttk.Label(self, text="Hora de encendido").pack(pady=(10, 0))

        frame_on = ttk.Frame(self)
        frame_on.pack(pady=5)

        ttk.Label(frame_on, text="Hora:").grid(row=0, column=0, padx=2)
        self.entryHourOn = ttk.Entry(frame_on, width=3)
        self.entryHourOn.grid(row=0, column=1, padx=2)

        ttk.Label(frame_on, text="Minuto:").grid(row=0, column=2, padx=2)
        self.entryMinuteOn = ttk.Entry(frame_on, width=3)
        self.entryMinuteOn.grid(row=0, column=3, padx=2)

        # Hora de apagado
        ttk.Label(self, text="Hora de apagado").pack(pady=(10, 0))

        frame_off = ttk.Frame(self)
        frame_off.pack(pady=5)

        ttk.Label(frame_off, text="Hora:").grid(row=0, column=0, padx=2)
        self.entryHourOff = ttk.Entry(frame_off, width=3)
        self.entryHourOff.grid(row=0, column=1, padx=2)

        ttk.Label(frame_off, text="Minuto:").grid(row=0, column=2, padx=2)
        self.entryMinuteOff = ttk.Entry(frame_off, width=3)
        self.entryMinuteOff.grid(row=0, column=3, padx=2)

        # Botones de acción
        btns = ttk.Frame(self, padding=10)
        btns.pack()

        ttk.Button(
            btns,
            text="Enviar configuración a la Pico",
            command=self.enviar_config
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        ttk.Button(
            btns,
            text="Encender LED manualmente",
            command=self.encender_manual
        ).grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        ttk.Button(
            btns,
            text="Apagar LED manualmente",
            command=self.apagar_manual
        ).grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        # Label de estado
        self.label_status = ttk.Label(self, text="", foreground="blue", padding=10)
        self.label_status.pack(anchor="w")

        # Para que la pestaña tenga refresco compatible con MainView._refresh_type_tabs
        # (aunque aquí no hacemos nada especial).
        # Esto evita errores cuando MainView llama tab.refresh_state().
    def refresh_state(self):
        pass

    # -------------------------------------------------
    # Función auxiliar para enviar datos a la Pico
    # -------------------------------------------------
    def _enviar_a_pico(self, line: str, msg_ok: str, msg_error_prefix: str):
        if not self.pico:
            self.label_status.config(text="No hay enlace configurado con la Pico.")
            return

        resp = self.pico.send_line(line)
        # Consideramos error solo los problemas claros de enlace
        if resp.startswith("ERR NO_PICO") or resp.startswith("ERR SEND"):
            self.label_status.config(text=f"{msg_error_prefix}: {resp}")
        else:
            # Puede devolver algo como 'OK ...' o incluso 'ERR NO_RESP'
            # pero el comando ya se envió por el canal unificado (WiFi/USB).
            self.label_status.config(text=f"{msg_ok} (resp: {resp})")

    # -------------------------------------------------
    # Enviar configuración de horarios (modo automático)
    # Formato: hora_now;min_now;hora_on;min_on;hora_off;min_off
    # -------------------------------------------------
    def _registrar_evento_presencia(self, estado: str):
        """
        estado: 'encendida' o 'apagada'
        """
        did = None
        # Buscar, si existe, un dispositivo de tipo "Simulador de presencia"
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            r = cx.execute(
                "SELECT id FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",
                (self.user.id, "Simulador de presencia")
            ).fetchone()
            if r:
                did = r["id"]

        msg = f"Simulador de presencia: luz {estado}"

        # Evento en bitácora
        self.repo.add_event(
            self.user.id,
            did,
            type_="presence",
            severity="low",
            message=msg,
            image_path=None,
            extra={"source": "presence_tab", "state": estado}
        )

        # Notificación (como hace QuickActions._notify)
        self.repo.add_notification(
            self.user.id,
            channel="inapp",
            priority="normal",
            title="Presencia",
            body=msg,
            status="sent"
        )

        # Banner en pantalla
        self.banner.show(msg, "info")

    def enviar_config(self):
        try:
            hour_now    = int(self.entryHourNow.get())
            minute_now  = int(self.entryMinuteNow.get())
            hour_on     = int(self.entryHourOn.get())
            minute_on   = int(self.entryMinuteOn.get())
            hour_off    = int(self.entryHourOff.get())
            minute_off  = int(self.entryMinuteOff.get())
        except ValueError:
            self.label_status.config(text="Error: todos los campos deben ser números enteros")
            return

        linea = f"{hour_now};{minute_now};{hour_on};{minute_on};{hour_off};{minute_off}"
        self._enviar_a_pico(
            linea,
            "Configuración enviada a la Pico.",
            "Error al enviar configuración"
        )

    # -------------------------------------------------
    # Encender LED en modo manual
    # -------------------------------------------------
    def encender_manual(self):
        self._enviar_a_pico(
            "ON",
            "Comando ON enviado a la Pico.",
            "Error ON"
        )
        # NUEVO: registrar evento y notificación
        self._registrar_evento_presencia("encendida")

    # -------------------------------------------------
    # Apagar LED en modo manual
    # -------------------------------------------------
    def apagar_manual(self):
        self._enviar_a_pico(
            "OFF",
            "Comando OFF enviado a la Pico.",
            "Error OFF"
        )
        # NUEVO: registrar evento y notificación
        self._registrar_evento_presencia("apagada")


class QuickActions(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, banner: Banner):
        super().__init__(master); self.repo=repo; self.user=user; self.banner=banner
        ttk.Label(self, text="Simulador de dispositivos (para pruebas)", font=("Segoe UI", 10, 'bold')).pack(anchor='w', padx=8, pady=(8,0))
        grid = ttk.Frame(self); grid.pack(fill='x', padx=8, pady=6)
        buttons = [("Detector movimiento", self.detect_motion),("Humo detectado", self.smoke_alert),("Cámara: foto por mov.", self.camera_capture),("Simulador presencia", self.presence_tick),("Silenciosa", self.panic_button),("Puerta/ventana cambio", self.door_window_toggle),("Boton de panico", self.silent_alarm),("Barrera láser", self.laser_barrier),("LPR (placa)", self.lpr_event)]
        for i,(txt,cmd) in enumerate(buttons): ttk.Button(grid, text=txt, command=cmd).grid(row=i//2, column=i%2, sticky='ew', padx=4, pady=4)
        for c in range(2): grid.columnconfigure(c, weight=1)
    def _pick_device(self, type_hint: Optional[str]=None) -> Optional[int]:
        with sqlite3.connect(self.repo.path) as cx:
            cx.row_factory = sqlite3.Row
            if type_hint:
                r = cx.execute("SELECT id FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",(self.user.id, type_hint)).fetchone()
                if r: return r['id']
            r = cx.execute("SELECT id FROM devices WHERE user_id=? ORDER BY id LIMIT 1",(self.user.id,)).fetchone()
            return r['id'] if r else None
    def _notify(self, title: str, body: str, priority=False):
        self.repo.add_notification(self.user.id, 'inapp', 'alta' if priority else 'normal', title, body, 'sent')
        self.banner.show(f"{title}: {body}", 'priority' if priority else 'info')
    def detect_motion(self):
        did = self._pick_device("Detector de movimiento"); self.repo.add_event(self.user.id, did, 'motion', 'high', 'Movimiento detectado', None, {}); self._notify('Movimiento', 'Se detectó movimiento', priority=True); play_beep(1200, 250)
    def smoke_alert(self):
        did = self._pick_device("Sensor de humo"); self.repo.add_event(self.user.id, did, 'smoke', 'critical', 'Humo detectado', None, {}); self._notify('Humo', '¡Alerta crítica!', priority=True); play_beep(1400, 300)
    def camera_capture(self):
        did = self._pick_device("Cámara con foto por movimiento"); self.repo.add_event(self.user.id, did, 'camera', 'high', 'Foto capturada por movimiento', None, {}); self._notify('Cámara', 'Imagen adjunta')
    def presence_tick(self): did = self._pick_device("Simulador de presencia"); self.repo.add_event(self.user.id, did, 'presence', 'low', 'Simulador accionó luz', None, {}); self._notify('Presencia', 'Luz conmutada')
    def panic_button(self): did = self._pick_device("Silenciosa"); self.repo.add_event(self.user.id, did, 'silent', 'critical', 'Alarma silenciosa', None, {}); self._notify('Silenciosa', 'Alerta urgente', priority=True); play_beep(1600, 400)
    def door_window_toggle(self):
        did = self._pick_device("Puertas/ventanas"); row = self.repo.get_device(did) if did else None; new_state = 'open' if (row and row['status']!='open') else 'closed'
        if did: self.repo.set_device_status(did, new_state)
        self.repo.add_event(self.user.id, did, 'doorwin', 'medium', f"Estado {new_state}", None, {}); self._notify('Puerta/Ventana', f"{new_state}")
    def silent_alarm(self):
        did = self._pick_device("Alarma silenciosa"); self.repo.add_event(self.user.id, did, 'silent_alarm', 'critical', 'Alarma silenciosa activada', None, {}); self.banner.show("Alarma silenciosa: alerta enviada", 'priority'); self.repo.add_notification(self.user.id, 'inapp', 'alta', 'Alarma silenciosa', 'Alerta enviada', 'sent')
    def laser_barrier(self):
        did = self._pick_device("Barrera láser"); self.repo.add_event(self.user.id, did, 'laser_start', 'high', 'Barrera interrumpida (inicio)', None, {}); self._notify('Barrera láser', 'Interrupción detectada')
        def end_event(): self.repo.add_event(self.user.id, did, 'laser_end', 'high', 'Barrera interrumpida (fin)', None, {"duration_s":2})
        threading.Timer(2.0, end_event).start()
    def lpr_event(self):
        did = self._pick_device("Reconocimiento de placas"); plate = "ABC123"; authorized = False; msg = f"Placa {plate} {'autorizada' if authorized else 'NO autorizada'}"
        self.repo.add_event(self.user.id, did, 'lpr', 'high' if not authorized else 'low', msg, None, {"plate": plate, "authorized": authorized})
        if not authorized: self._notify('LPR', 'Vehículo no registrado', priority=True)

class MainView(ttk.Frame):
    def __init__(self, master, repo: Repo, user: User, pico_unified:PicoUnified):
        super().__init__(master); self.master.title("Ving — Panel principal"); self.repo=repo; self.user=user; self.pico=pico_unified
        self.banner = Banner(self)
        nb = ttk.Notebook(self); nb.pack(fill='both', expand=True, padx=4, pady=4); self.nb = nb
        self.tab_devices = DevicesTab(nb, self.repo, self.user, self.banner, on_event=self._on_event)
        self.tab_events  = EventsTab(nb, self.repo, self.user, self.banner)
        self.tab_hist    = HistogramTab(nb, self.repo, self.user, self.banner)
        self.tab_lock    = LockTab(nb, self.repo, self.user, self.banner, pico=self.pico)
        self.tab_motion = MotionSensorTab(nb, self.repo, self.user, self.banner)
        self.tab_smoke   = DeviceTypeTab(nb, self.repo, self.user, self.banner, device_type="Sensor de humo", title="Panel específico — Sensor de humo")
        self.tab_camera  = CameraTab(nb, self.repo, self.user, self.banner)
        self.tab_presence = PresenceSimTab(nb, self.repo, self.user, self.banner, pico=self.pico)
        self.tab_panic   = DeviceTypeTab(
            nb,
            self.repo,
            self.user,
            self.banner,
            device_type="Alarma Silenciosa",
            title="Panel específico — Alarma silenciosa",
            require_device=False         # ← clave
        )
        self.tab_panic.btn_action.config(text="Activar Alarma silenciosa")
        for c in self.tab_panic.btn_frame.winfo_children():
            c.pack_forget()  # quitamos el pack anterior ("side='left'")

        self.tab_panic.btn_action.pack(pady=20)  # lo volvemos a agregar centrado

        # Estilo rojo con borde marcado
        style = ttk.Style()
        style.configure(
            "Panic.TButton",
            foreground="white",
            background="#cc0000",
            borderwidth=4,
            relief="raised"
        )
        style.map(
            "Panic.TButton",
            background=[("active", "#ff0000")],
            relief=[("pressed", "sunken"), ("!pressed", "raised")]
        )
        def panic_sim():
            # Buscar (opcionalmente) un dispositivo de tipo "Botón de pánico"
            did = None
            with sqlite3.connect(self.repo.path) as cx:
                cx.row_factory = sqlite3.Row
                r = cx.execute(
                    "SELECT id FROM devices WHERE user_id=? AND type=? ORDER BY id LIMIT 1",
                    (self.user.id, "Botón de pánico")
                ).fetchone()
                if r:
                    did = r["id"]

            # Registrar SIEMPRE un evento de pánico, aunque did sea None
            self.repo.add_event(
                self.user.id,
                did,
                type_="Silenciosa",
                severity="critical",
                message="Alarma Silenciosa activada",
                image_path=None,
                extra={"source": "desktop_panic_tab"}
            )

            # Mostrar notificación visual y sonora
            self.banner.show("Alarma Silenciosa activada", "priority")
            play_beep(1600, 400)

            # Refrescar la bitácora para verlo de una vez
            self.tab_events.refresh()

        # Reemplazar el comando del botón genérico por el de pánico
        self.tab_panic.btn_action.configure(command=panic_sim)

        self.tab_panic.btn_action.configure(style="Panic.TButton")
        self.tab_doorwin = DeviceTypeTab(nb, self.repo, self.user, self.banner, device_type="Puertas/ventanas", title="Panel específico — Puertas/ventanas")
        self.tab_silent  = DeviceTypeTab(nb, self.repo, self.user, self.banner, device_type="Alarma silenciosa", title="Panel específico — Alarma silenciosa")
        self.tab_laser   = DeviceTypeTab(nb, self.repo, self.user, self.banner, device_type="Barrera láser", title="Panel específico — Barrera láser")
        self.tab_lpr     = LprTab(nb, self.repo, self.user, self.banner)
        self.tab_quick   = QuickActions(nb, self.repo, self.user, self.banner)
        nb.add(self.tab_devices, text='Dispositivos'); nb.add(self.tab_events,  text='Bitácora'); nb.add(self.tab_hist,    text='Histograma'); nb.add(self.tab_lock,    text='Cerraduras')
        nb.add(self.tab_motion,  text='Movimiento');  nb.add(self.tab_smoke,   text='Humo');     nb.add(self.tab_camera,  text='Cámara');     nb.add(self.tab_presence,text='Presencia')
        nb.add(self.tab_panic,   text='Silenciosa');      nb.add(self.tab_doorwin, text='Puertas/Vent.'); nb.add(self.tab_silent,  text='Silenciosa'); nb.add(self.tab_laser,   text='Láser')
        nb.add(self.tab_lpr,     text='Placas');      nb.add(self.tab_quick,   text='Simulador')
        hdr = ttk.Frame(self, padding=6); hdr.pack(fill='x', side='top')
        ttk.Label(hdr, text=f"Bienvenido, {user.name}", font=("Segoe UI", 12, 'bold')).pack(side='left')
        ttk.Button(hdr, text="Cerrar sesión", command=self._logout).pack(side='right')
        self.pack(fill='both', expand=True); self._refresh_type_tabs()
    def _logout(self):
        if messagebox.askyesno("Salir", "¿Cerrar sesión?"): self.master.destroy(); main()
    def _on_event(self, kind=None, *args, **kwargs):
        self.tab_events.refresh()
        if kind == 'devices_changed': self._refresh_type_tabs()
    def _refresh_type_tabs(self):
        self.tab_lock.refresh_state()
        for tab in (self.tab_motion,self.tab_smoke,self.tab_camera,self.tab_presence,self.tab_panic,self.tab_doorwin,self.tab_silent,self.tab_laser,self.tab_lpr):
            tab.refresh_state()
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
        self.wifi = WiFiPicoBridge(host="0.0.0.0", port=12345, repo=self.repo)
        usb = UsbPicoLink(port="COM8").open()
        self.pico = PicoUnified(self.wifi, usb)
        self._show_login()

    def _show_login(self):
        for w in self.winfo_children():
            if isinstance(w, ttk.Notebook) or isinstance(w, ttk.Frame):
                w.destroy()
        LoginView(self, self.repo, on_login=self._show_main)

    def _show_main(self, user: User):
        for w in self.winfo_children():
            w.destroy()
        MainView(self, self.repo, user, pico_unified=self.pico)


def main():
    repo = Repo(DB_PATH)
    app = App(repo)
    app.mainloop()


if __name__ == '__main__':
    main()
