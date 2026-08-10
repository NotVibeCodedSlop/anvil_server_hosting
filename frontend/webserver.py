#!/usr/bin/env python3
"""
AnvilServerHosting - Web Gateway Server (frontend/webserver.py)
"""

import os
import sys
import re
import json
import time
import secrets
import hashlib
import sqlite3
import asyncio
import mimetypes
import urllib.request
from pathlib import Path
from urllib.parse import urlparse, parse_qs

mimetypes.init()

IS_WINDOWS = sys.platform == "win32"
BASE_DIR = Path.home() / ".local" / "share" / "AnvilServerHosting"
DB_PATH = BASE_DIR / "anvil.db"
SOCKET_PATH = BASE_DIR / "anvil.sock"
TCP_PORT = 5002
WEBPAGE_PATH = (Path(__file__).parent / "webpage").resolve()

MAX_FILE_SIZE = 100 * 1024 * 1024
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
SERVER_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
USER_AGENT = "AnvilServerHosting/1.0.0 (https://github.com/AnvilServerHosting)"

PWA_MANIFEST = {
    "name": "Anvil Server Hosting",
    "short_name": "AnvilHosting",
    "description": "Minecraft Server Management Engine PWA",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#080a0e",
    "theme_color": "#080a0e",
    "icons": [
        {
            "src": "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%233b82f6'/><text x='50%' y='68%' font-size='60' font-weight='bold' text-anchor='middle' fill='white'>⚡</text></svg>",
            "sizes": "192x192 512x512",
            "type": "image/svg+xml"
        }
    ]
}

SERVICE_WORKER_SCRIPT = """
const CACHE_NAME = 'anvil-pwa-v1';
const ASSETS = ['/', '/main.html'];

self.addEventListener('install', (e) => {
    e.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
    self.skipWaiting();
});

self.addEventListener('activate', (e) => {
    e.waitUntil(clients.claim());
});

self.addEventListener('fetch', (e) => {
    if (e.request.url.includes('/api/')) {
        e.respondWith(fetch(e.request));
        return;
    }
    e.respondWith(
        caches.match(e.request).then((cached) => cached || fetch(e.request))
    );
});
"""


def hash_password_sync(password: str, salt_hex: str = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return dk.hex(), salt.hex()


def compute_server_id(username: str, display_name: str) -> str:
    user_hash = hashlib.sha1(username.lower().encode('utf-8')).hexdigest()
    srv_hash = hashlib.sha1(display_name.lower().encode('utf-8')).hexdigest()
    return hashlib.sha1((user_hash + srv_hash).encode('utf-8')).hexdigest()[:16]


def safe_resolve_path(server_dir: Path, rel_path: str) -> Path:
    clean_rel = rel_path.lstrip("/\\") if rel_path else ""
    target = (server_dir / clean_rel).resolve()
    if not target.is_relative_to(server_dir.resolve()):
        raise PermissionError("Path traversal attack detected.")
    return target


def get_real_client_ip(headers: dict, peer_ip: str) -> str:
    if "cf-connecting-ip" in headers:
        return headers["cf-connecting-ip"].strip()
    if "x-forwarded-for" in headers:
        return headers["x-forwarded-for"].split(",")[0].strip()
    return peer_ip


def get_db():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL, salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user', group_id TEXT DEFAULT 'default',
                is_suspended INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
                max_instances INTEGER NOT NULL DEFAULT 3, max_ram_mb INTEGER NOT NULL DEFAULT 4096,
                max_cpu_pct INTEGER NOT NULL DEFAULT 100, max_disk_mb INTEGER NOT NULL DEFAULT 10000
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at REAL NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)
        """)
        # Seed default system settings
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('allow_registration', 'true')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('lock_online_mode', 'false')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('max_view_distance', '16')")
        conn.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('max_simulation_distance', '12')")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS presets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                loader TEXT NOT NULL DEFAULT 'all',
                project_ids TEXT NOT NULL,
                owner_id TEXT DEFAULT 'system',
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            INSERT OR IGNORE INTO groups (id, name, max_instances, max_ram_mb, max_cpu_pct, max_disk_mb)
            VALUES ('default', 'Default Users', 3, 4096, 100, 10000)
        """)

        admin_exists = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
        if not admin_exists:
            salt = secrets.token_bytes(32)
            dk = hashlib.pbkdf2_hmac('sha256', b'admin123', salt, 100000)
            conn.execute("""
                INSERT OR IGNORE INTO users (id, username, password_hash, salt, role, group_id, is_suspended, created_at)
                VALUES ('admin_01', 'admin', ?, ?, 'admin', 'default', 0, ?)
            """, (dk.hex(), salt.hex(), time.strftime("%Y-%m-%dT%H:%M:%SZ")))
            print("\n⚡ Default Admin Account Created (admin / admin123)\n", flush=True)

        # Auto-seed Default Global Optimization & Utility Presets
        presets_seed = [
            (
                'preset_opt_fabric',
                '⚡ Ultimate Optimization Pack',
                'Maximum server performance with multithreading, memory reduction, and optimized ticking. Includes Fabric API.',
                'fabric',
                json.dumps(['fabric-api', 'lithium', 'ferrite-core', 'c2me-fabric', 'krypton', 'spark']),
                'system',
                time.strftime("%Y-%m-%dT%H:%M:%SZ")
            ),
            (
                'preset_crossplay_paper',
                '🌐 Bedrock Crossplay & Pre-generation',
                'Allows Bedrock Edition players to join and pre-generates chunks to stop lag.',
                'paper',
                json.dumps(['geyser', 'floodgate', 'viaversion', 'chunky']),
                'system',
                time.strftime("%Y-%m-%dT%H:%M:%SZ")
            ),
            (
                'preset_admin_tools',
                '🛡️ Essential Admin & Protection Suite',
                'Permission management, rollback logging, and core server utilities.',
                'paper',
                json.dumps(['luckperms', 'coreprotect', 'essentialsx', 'chunky']),
                'system',
                time.strftime("%Y-%m-%dT%H:%M:%SZ")
            )
        ]

        for p in presets_seed:
            conn.execute("INSERT OR REPLACE INTO presets (id, name, description, loader, project_ids, owner_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", p)

    return conn


def http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=8.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def query_daemon(action: str, params: dict = None) -> dict:
    writer = None
    try:
        if IS_WINDOWS:
            reader, writer = await asyncio.open_connection('127.0.0.1', TCP_PORT)
        else:
            if not SOCKET_PATH.exists():
                return {"status": "failure", "error": "Daemon process is not running."}
            reader, writer = await asyncio.open_unix_connection(str(SOCKET_PATH))

        payload = json.dumps({"action": action, "params": params or {}}).encode('utf-8') + b"\n"
        writer.write(payload)
        await writer.drain()

        response_bytes = await reader.readline()
        if not response_bytes:
            return {"status": "failure", "error": "Daemon unavailable."}

        return json.loads(response_bytes.decode('utf-8'))

    except (ConnectionRefusedError, FileNotFoundError):
        return {"status": "failure", "error": "Daemon process is not running."}
    except Exception:
        return {"status": "failure", "error": "Internal communication error."}
    finally:
        if writer:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass


def get_session_user(headers: dict) -> dict:
    cookie_str = headers.get("cookie", "")
    session_token = None
    for item in cookie_str.split(";"):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            if k == "anvil_session": session_token = v; break

    if not session_token: return None
    conn = get_db()
    row = conn.execute("""
        SELECT users.id, users.username, users.role, users.is_suspended, users.group_id FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE sessions.token = ? AND sessions.expires_at > ?
    """, (session_token, time.time())).fetchone()

    if row and row["is_suspended"] == 0:
        return {"id": row["id"], "username": row["username"], "role": row["role"], "group_id": row["group_id"], "token": session_token}
    return None


def get_modrinth_loader_tags(srv_loader: str) -> list[str]:
    srv_loader = (srv_loader or "paper").lower().strip()
    if srv_loader in {"paper", "spigot"}: return ["paper", "spigot", "bukkit"]
    elif srv_loader == "folia": return ["folia", "paper", "spigot", "bukkit"]
    elif srv_loader in {"waterfall", "travertine"}: return ["waterfall", "bungeecord"]
    elif srv_loader == "velocity": return ["velocity"]
    elif srv_loader == "fabric": return ["fabric"]
    elif srv_loader == "neoforge": return ["neoforge", "forge"]
    elif srv_loader == "quilt": return ["quilt", "fabric"]
    elif srv_loader == "vanilla": return ["datapack", "vanilla"]
    return [srv_loader]


async def purge_expired_sessions_loop():
    while True:
        try:
            conn = get_db()
            with conn: conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        except Exception: pass
        await asyncio.sleep(3600)


async def handle_api(method: str, path: str, query: dict, body: dict, headers: dict, body_bytes: bytes = b"") -> tuple[int, dict, list]:
    conn = get_db()
    is_https = (headers.get("x-forwarded-proto") == "https") or (headers.get("cf-visitor", "").find("https") != -1)

    # 1. PUBLIC ENDPOINTS
    if method == "GET" and path == "/api/mc-versions":
        try:
            manifest = http_get_json("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json")
            releases = [{"id": v["id"], "type": v["type"]} for v in manifest.get("versions", []) if v.get("type") == "release"]
            return 200, {
                "status": "success",
                "latest": manifest.get("latest", {}).get("release"),
                "versions": releases
            }, []
        except Exception as e:
            return 500, {"status": "failure", "error": f"Could not fetch Mojang manifest: {str(e)}"}, []

    if method == "GET" and path == "/api/auth/status":
        reg_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'allow_registration'").fetchone()
        is_allowed = (reg_setting["value"] != "false") if reg_setting else True
        return 200, {"status": "success", "allow_registration": is_allowed}, []

    elif method == "POST" and path == "/api/auth/register":
        reg_lock = conn.execute("SELECT value FROM system_settings WHERE key = 'allow_registration'").fetchone()
        if reg_lock and reg_lock["value"] == "false":
            return 403, {"status": "failure", "error": "Public registration is currently disabled by administrator."}, []

        username = body.get("username", "").strip()
        password = body.get("password", "").strip()
        if not USERNAME_REGEX.match(username) or len(password) < 6:
            return 400, {"status": "failure", "error": "Invalid username (3-20 chars) or password (6+ chars)."}, []

        pwd_hash, salt_hex = await asyncio.to_thread(hash_password_sync, password)
        user_id = secrets.token_hex(8)

        try:
            with conn:
                conn.execute("""
                    INSERT INTO users (id, username, password_hash, salt, role, group_id, is_suspended, created_at)
                    VALUES (?, ?, ?, ?, 'user', 'default', 0, ?)
                """, (user_id, username, pwd_hash, salt_hex, time.strftime("%Y-%m-%dT%H:%M:%SZ")))
        except sqlite3.IntegrityError:
            return 400, {"status": "failure", "error": "Username taken."}, []

        return 200, {"status": "success", "message": "Registered successfully."}, []

    elif method == "POST" and path == "/api/auth/login":
        username = body.get("username", "").strip()
        password = body.get("password", "").strip()

        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user or user["is_suspended"] == 1:
            return 401, {"status": "failure", "error": "Invalid login or suspended account."}, []

        expected_hash, _ = await asyncio.to_thread(hash_password_sync, password, user["salt"])
        if not secrets.compare_digest(expected_hash, user["password_hash"]):
            return 401, {"status": "failure", "error": "Invalid login or suspended account."}, []

        session_token = secrets.token_hex(32)
        expires_at = time.time() + (86400 * 7)

        with conn:
            conn.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
                         (session_token, user["id"], expires_at))

        secure_flag = "; Secure" if is_https else ""
        cookie_hdr = f"Set-Cookie: anvil_session={session_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800{secure_flag}"
        return 200, {"status": "success", "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}, [cookie_hdr]

    elif method == "POST" and path == "/api/auth/logout":
        user = get_session_user(headers)
        if user:
            with conn: conn.execute("DELETE FROM sessions WHERE token = ?", (user["token"],))
        cookie_hdr = "Set-Cookie: anvil_session=; Path=/; HttpOnly; Max-Age=0"
        return 200, {"status": "success"}, [cookie_hdr]

    elif method == "GET" and path == "/api/auth/me":
        user = get_session_user(headers)
        if not user: return 401, {"status": "failure", "error": "Not authenticated."}, []
        return 200, {"status": "success", "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}, []

    # 2. CHECK SESSION AUTHENTICATION
    user = get_session_user(headers)
    if not user: return 401, {"status": "failure", "error": "Unauthorized session."}, []

    if method == "POST" and path == "/api/auth/change_password":
        new_pwd = body.get("new_password", "").strip()
        if len(new_pwd) < 6: return 400, {"status": "failure", "error": "Min 6 characters required."}, []
        pwd_hash, salt_hex = await asyncio.to_thread(hash_password_sync, new_pwd)
        with conn: conn.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (pwd_hash, salt_hex, user["id"]))
        return 200, {"status": "success", "message": "Password changed successfully."}, []

    # 3. GLOBAL SERVER ID RESOLUTION & PERMISSIONS
    srv_id = (body.get("id") or body.get("name") or query.get("name", [""])[0] or query.get("id", [""])[0]).strip()
    if srv_id:
        srv_row = conn.execute("SELECT owner_id FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id)).fetchone()
        if srv_row:
            if srv_row["owner_id"] in ("system", "", None):
                with conn: conn.execute("UPDATE servers SET owner_id = ? WHERE id = ? OR name = ?", (user["id"], srv_id, srv_id))
            elif srv_row["owner_id"] != user["id"] and user["role"] != "admin":
                return 403, {"status": "failure", "error": "Access denied."}, []

    # --------------------------------------------------------------------------
    # ADMIN PANEL APIS
    # --------------------------------------------------------------------------
    if path.startswith("/api/admin/"):
        if user["role"] != "admin": return 403, {"status": "failure", "error": "Admin required."}, []

        if method == "GET" and path == "/api/admin/users":
            users = conn.execute("SELECT id, username, role, group_id, is_suspended, created_at FROM users").fetchall()
            return 200, {"status": "success", "users": [dict(u) for u in users]}, []

        elif method == "POST" and path == "/api/admin/users/create":
            uname, pwd, role = body.get("username", "").strip(), body.get("password", "").strip(), body.get("role", "user")
            if not USERNAME_REGEX.match(uname) or len(pwd) < 6:
                return 400, {"status": "failure", "error": "Invalid username or password."}, []
            pwd_hash, salt_hex = await asyncio.to_thread(hash_password_sync, pwd)
            new_uid = secrets.token_hex(8)
            try:
                with conn: conn.execute("INSERT INTO users (id, username, password_hash, salt, role, group_id, is_suspended, created_at) VALUES (?, ?, ?, ?, ?, 'default', 0, ?)", (new_uid, uname, pwd_hash, salt_hex, role, time.strftime("%Y-%m-%dT%H:%M:%SZ")))
                return 200, {"status": "success", "message": f"User '{uname}' created."}, []
            except sqlite3.IntegrityError: return 400, {"status": "failure", "error": "Username taken."}, []

        elif method == "POST" and path == "/api/admin/users/suspend":
            with conn: conn.execute("UPDATE users SET is_suspended = ? WHERE id = ?", (1 if body.get("suspend") else 0, body.get("user_id")))
            return 200, {"status": "success", "message": "User status updated."}, []
        elif method == "GET" and path == "/api/admin/servers":
            rows = conn.execute("""
                SELECT servers.*, users.username as owner_username 
                FROM servers 
                LEFT JOIN users ON servers.owner_id = users.id
            """).fetchall()
            return 200, {"status": "success", "servers": [dict(r) for r in rows]}, []

        elif method == "GET" and path == "/api/admin/groups":
            groups = conn.execute("SELECT * FROM groups").fetchall()
            return 200, {"status": "success", "groups": [dict(g) for g in groups]}, []
#        HUB MULTIPLEXER APIS
        elif method == "GET" and path == "/api/admin/hub":
            res = await query_daemon("get_hub_status")
            mode_row = conn.execute("SELECT value FROM system_settings WHERE key = 'hub_mode'").fetchone()
            domain_row = conn.execute("SELECT value FROM system_settings WHERE key = 'hub_custom_domain'").fetchone()
            res["mode"] = mode_row["value"] if mode_row else "chat_code"
            res["custom_domain"] = domain_row["value"] if domain_row else ""
            return 200, res, []

        elif method == "POST" and path == "/api/admin/hub/start":
            res = await query_daemon("start_hub")
            return 200, res, []

        elif method == "POST" and path == "/api/admin/hub/stop":
            res = await query_daemon("stop_hub")
            return 200, res, []

        elif method == "POST" and path == "/api/admin/hub/settings":
            mode = body.get("mode", "chat_code")
            domain = body.get("custom_domain", "").strip()
            with conn:
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('hub_mode', ?)", (mode,))
                conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('hub_custom_domain', ?)", (domain,))
            return 200, {"status": "success", "message": "Hub router settings saved."}, []
        elif method == "POST" and path == "/api/admin/groups/save":
            group_id = body.get("id", "default")
            name = body.get("name", "Default Users")
            max_instances = int(body.get("max_instances", 3))
            max_ram_mb = int(body.get("max_ram_mb", 4096))
            max_cpu_pct = int(body.get("max_cpu_pct", 100))
            max_disk_mb = int(body.get("max_disk_mb", 10000))
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO groups (id, name, max_instances, max_ram_mb, max_cpu_pct, max_disk_mb)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (group_id, name, max_instances, max_ram_mb, max_cpu_pct, max_disk_mb))
            return 200, {"status": "success", "message": f"Group '{name}' quotas updated."}, []

        elif method == "POST" and path == "/api/admin/users/assign_group":
            target_uid = body.get("user_id")
            target_gid = body.get("group_id", "default")
            with conn: conn.execute("UPDATE users SET group_id = ? WHERE id = ?", (target_gid, target_uid))
            return 200, {"status": "success", "message": "User group updated."}, []

        elif method == "GET" and path == "/api/admin/settings":
            settings = conn.execute("SELECT * FROM system_settings").fetchall()
            return 200, {"status": "success", "settings": {s["key"]: s["value"] for s in settings}}, []

        elif method == "POST" and path == "/api/admin/settings":
            updates = body.get("settings", {})
            with conn:
                for k, v in updates.items():
                    conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (k, str(v)))
            return 200, {"status": "success", "message": "Global settings saved."}, []

    # 4. INSTANCE MANAGEMENT APIS
    if method == "GET" and path == "/api/servers":
        res = await query_daemon("list_servers", {"owner_id": user["id"] if user["role"] != "admin" else None})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/create":
        display_name = body.get("name", "").strip()
        mc_ver = body.get("minecraftversion", "1.20.4")
        loader = body.get("loader", "paper")
        backend = body.get("backend", "podman")
        if not SERVER_NAME_REGEX.match(display_name): return 400, {"status": "failure", "error": "Invalid server name."}, []

        # Disk Quota Check
        disk_res = await query_daemon("get_user_disk_usage", {"owner_id": user["id"]})
        used_disk_mb = disk_res.get("used_disk_mb", 0)
        group = conn.execute("SELECT max_disk_mb, max_instances FROM groups WHERE id = ?", (user["group_id"],)).fetchone()
        max_disk_mb = group["max_disk_mb"] if group else 10000
        max_instances = group["max_instances"] if group else 3

        if user["role"] != "admin":
            curr_instances = conn.execute("SELECT COUNT(*) as count FROM servers WHERE owner_id = ?", (user["id"],)).fetchone()["count"]
            if curr_instances >= max_instances:
                return 400, {"status": "failure", "error": f"Instance quota reached ({curr_instances}/{max_instances})."}, []
            if used_disk_mb >= max_disk_mb:
                return 400, {"status": "failure", "error": f"Storage quota exceeded ({used_disk_mb}/{max_disk_mb} MB)."}, []

        hashed_id = compute_server_id(user["username"], display_name)
        res = await query_daemon("create_server", {
            "id": hashed_id, "display_name": display_name, "owner_id": user["id"],
            "minecraftversion": mc_ver, "loader": loader, "backend": backend
        })
        return 200, res, []

    elif method == "POST" and path == "/api/servers/delete":
        if not srv_id: return 400, {"status": "failure", "error": "Missing server identifier."}, []
        with conn: conn.execute("DELETE FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id))
        res = await query_daemon("delete_server", {"name": srv_id})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/start":
        # Check quota before starting
        disk_res = await query_daemon("get_user_disk_usage", {"owner_id": user["id"]})
        used_disk_mb = disk_res.get("used_disk_mb", 0)
        group = conn.execute("SELECT max_disk_mb FROM groups WHERE id = ?", (user["group_id"],)).fetchone()
        max_disk_mb = group["max_disk_mb"] if group else 10000

        if used_disk_mb >= max_disk_mb and user["role"] != "admin":
            return 400, {"status": "failure", "error": f"Storage Quota Exceeded ({used_disk_mb} MB / {max_disk_mb} MB limit). Cannot start instance."}, []

        res = await query_daemon("start_server", {"name": srv_id})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/stop":
        res = await query_daemon("stop_server", {"name": srv_id})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/console":
        res = await query_daemon("send_command", {"name": srv_id, "command": body.get("command", "")})
        return 200, res, []

    elif method == "GET" and path == "/api/servers/console":
        res = await query_daemon("get_console", {"name": srv_id})
        return 200, res, []

    # 5. FILE MANAGER APIS
    elif method == "GET" and path == "/api/servers/files":
        res = await query_daemon("list_files", {"name": srv_id, "path": query.get("path", [""])[0]})
        return 200, res, []

    elif method == "GET" and path == "/api/servers/files/download":
        file_path = query.get("path", [""])[0]
        server_dir = BASE_DIR / "mcservers" / srv_id
        try:
            target_file = safe_resolve_path(server_dir, file_path)
            if not target_file.exists() or target_file.is_dir():
                return 404, {"status": "failure", "error": "File not found."}, []

            raw_bytes = target_file.read_bytes()
            ctype, _ = mimetypes.guess_type(str(target_file))
            if not ctype: ctype = "application/octet-stream"

            headers_list = [
                f"Content-Type: {ctype}",
                f"Content-Disposition: attachment; filename=\"{target_file.name}\"",
                f"Content-Length: {len(raw_bytes)}"
            ]
            return 200, {"_raw_binary": raw_bytes, "headers": headers_list}, []
        except Exception as e:
            return 500, {"status": "failure", "error": f"Download failed: {str(e)}"}, []

    elif method == "POST" and path == "/api/servers/files/save":
        res = await query_daemon("save_file", {"name": srv_id, "path": body.get("path", ""), "content": body.get("content", "")})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/files/delete":
        res = await query_daemon("delete_file", {"name": srv_id, "path": body.get("path", "")})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/files/create_folder":
        res = await query_daemon("create_folder", {"name": srv_id, "path": body.get("path", "")})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/files/upload":
        filename = query.get("filename", ["file.txt"])[0]
        rel_path = query.get("path", [""])[0]
        full_rel = f"{rel_path}/{filename}" if rel_path else filename

        server_dir = BASE_DIR / "mcservers" / srv_id
        try:
            target_path = safe_resolve_path(server_dir, full_rel)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(body_bytes)
            return 200, {"status": "success", "message": f"Uploaded '{filename}'."}, []
        except Exception as e:
            return 500, {"status": "failure", "error": f"Upload failed: {str(e)}"}, []

    # 6. CONFIG & DISTANCE LIMITS
    elif method == "GET" and path == "/api/servers/config":
        res = await query_daemon("get_config", {"name": srv_id})

        max_vd = conn.execute("SELECT value FROM system_settings WHERE key = 'max_view_distance'").fetchone()
        max_sd = conn.execute("SELECT value FROM system_settings WHERE key = 'max_simulation_distance'").fetchone()
        lock_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'lock_online_mode'").fetchone()

        res["max_view_distance"] = int(max_vd["value"]) if max_vd else 16
        res["max_simulation_distance"] = int(max_sd["value"]) if max_sd else 12

        # Force online-mode to true if locked
        if lock_setting and lock_setting["value"] == "true":
            res["online_mode_locked"] = True
            if "properties" in res:
                res["properties"]["online-mode"] = "true"

        return 200, res, []

    elif method == "POST" and path == "/api/servers/config":
        props = body.get("properties", {})

        max_vd_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'max_view_distance'").fetchone()
        max_sd_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'max_simulation_distance'").fetchone()
        lock_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'lock_online_mode'").fetchone()

        max_vd = int(max_vd_setting["value"]) if max_vd_setting else 16
        max_sd = int(max_sd_setting["value"]) if max_sd_setting else 12

        # FORCE ONLINE MODE TO TRUE IF LOCKED
        if lock_setting and lock_setting["value"] == "true":
            props["online-mode"] = "true"  # <--- FORCES TRUE (NO BYPASS)

        if user["role"] != "admin":
            if "view-distance" in props:
                try: props["view-distance"] = str(min(int(props["view-distance"]), max_vd))
                except ValueError: props["view-distance"] = str(max_vd)

            if "simulation-distance" in props:
                try: props["simulation-distance"] = str(min(int(props["simulation-distance"]), max_sd))
                except ValueError: props["simulation-distance"] = str(max_sd)

        res = await query_daemon("save_config", {"name": srv_id, "properties": props})
        return 200, res, []

    elif method == "POST" and path == "/api/servers/config":
        props = body.get("properties", {})
        max_vd_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'max_view_distance'").fetchone()
        max_sd_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'max_simulation_distance'").fetchone()
        lock_setting = conn.execute("SELECT value FROM system_settings WHERE key = 'lock_online_mode'").fetchone()

        max_vd = int(max_vd_setting["value"]) if max_vd_setting else 16
        max_sd = int(max_sd_setting["value"]) if max_sd_setting else 12

        if user["role"] != "admin":
            if "online-mode" in props and lock_setting and lock_setting["value"] == "true":
                props.pop("online-mode", None)
            if "view-distance" in props:
                try: props["view-distance"] = str(min(int(props["view-distance"]), max_vd))
                except ValueError: props["view-distance"] = str(max_vd)
            if "simulation-distance" in props:
                try: props["simulation-distance"] = str(min(int(props["simulation-distance"]), max_sd))
                except ValueError: props["simulation-distance"] = str(max_sd)

        res = await query_daemon("save_config", {"name": srv_id, "properties": props})
        return 200, res, []

    # 7. ACCOUNT QUOTA
    elif method == "GET" and path == "/api/account/quota":
        group = conn.execute("SELECT * FROM groups WHERE id = ?", (user["group_id"],)).fetchone()
        instance_count = conn.execute("SELECT COUNT(*) as count FROM servers WHERE owner_id = ?", (user["id"],)).fetchone()["count"]
        disk_res = await query_daemon("get_user_disk_usage", {"owner_id": user["id"]})
        used_disk_mb = disk_res.get("used_disk_mb", 0.0)

        max_instances = group["max_instances"] if group else 3
        max_disk_mb = group["max_disk_mb"] if group else 10000
        disk_pct = min(100.0, round((used_disk_mb / max_disk_mb) * 100, 1)) if max_disk_mb > 0 else 0.0

        return 200, {
            "status": "success",
            "username": user["username"],
            "role": user["role"],
            "group_name": group["name"] if group else "Default",
            "instances_used": instance_count,
            "instances_max": max_instances,
            "disk_used_mb": used_disk_mb,
            "disk_max_mb": max_disk_mb,
            "disk_pct": disk_pct
        }, []

    # 8. PRESETS
    elif method == "GET" and path == "/api/presets":
        loader_filter = query.get("loader", [""])[0].lower()
        rows = conn.execute("SELECT * FROM presets WHERE owner_id = 'system' OR owner_id = ?", (user["id"],)).fetchall()
        presets_list = []
        for r in rows:
            p_loader = r["loader"].lower()
            if loader_filter and p_loader not in ("all", loader_filter) and not (p_loader == "fabric" and loader_filter == "quilt"):
                continue
            presets_list.append({
                "id": r["id"], "name": r["name"], "description": r["description"],
                "loader": r["loader"], "project_ids": json.loads(r["project_ids"]),
                "is_system": (r["owner_id"] == "system"), "is_owner": (r["owner_id"] == user["id"])
            })
        return 200, {"status": "success", "presets": presets_list}, []

    elif method == "POST" and path == "/api/presets/create":
        name = body.get("name", "").strip()
        description = body.get("description", "").strip()
        loader = body.get("loader", "all").strip().lower()
        project_ids = body.get("project_ids", [])
        if not name or not project_ids:
            return 400, {"status": "failure", "error": "Preset name and mod slugs required."}, []

        preset_id = "preset_" + secrets.token_hex(6)
        owner_id = "system" if (user["role"] == "admin" and body.get("is_global")) else user["id"]
        with conn:
            conn.execute("INSERT INTO presets (id, name, description, loader, project_ids, owner_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         (preset_id, name, description, loader, json.dumps(project_ids), owner_id, time.strftime("%Y-%m-%dT%H:%M:%SZ")))
        return 200, {"status": "success", "message": f"Preset '{name}' created."}, []

    elif method == "POST" and path == "/api/presets/delete":
        preset_id = body.get("preset_id")
        preset = conn.execute("SELECT * FROM presets WHERE id = ?", (preset_id,)).fetchone()
        if not preset: return 404, {"status": "failure", "error": "Preset not found."}, []
        if preset["owner_id"] != user["id"] and user["role"] != "admin":
            return 403, {"status": "failure", "error": "Cannot delete this preset."}, []
        with conn: conn.execute("DELETE FROM presets WHERE id = ?", (preset_id,))
        return 200, {"status": "success", "message": "Preset deleted."}, []

    elif method == "POST" and path == "/api/presets/apply":
        preset_id = body.get("preset_id")
        preset = conn.execute("SELECT * FROM presets WHERE id = ?", (preset_id,)).fetchone()
        if not preset: return 404, {"status": "failure", "error": "Preset not found."}, []
# CLOUDFLARE TUNNEL APIS
        elif method == "GET" and path == "/api/admin/tunnel":
            res = await query_daemon("get_cf_tunnel_status")
            return 200, res, []

        elif method == "POST" and path == "/api/admin/tunnel/start":
            mode = body.get("mode", "quick")
            token = body.get("token", "").strip()
            res = await query_daemon("start_cf_tunnel", {"mode": mode, "token": token, "port": TCP_PORT - 1 or 5001})
            return 200, res, []

        elif method == "POST" and path == "/api/admin/tunnel/stop":
            res = await query_daemon("stop_cf_tunnel")
            return 200, res, []
        srv_row = conn.execute("SELECT loader, minecraftversion FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id)).fetchone()
        if not srv_row: return 400, {"status": "failure", "error": "Server instance not found."}, []

        srv_loader = srv_row["loader"].lower()
        srv_mc_ver = srv_row["minecraftversion"]
        preset_loader = preset["loader"].lower()

        # Strict Loader Match
        if preset_loader != "all" and preset_loader != srv_loader:
            if not (preset_loader == "fabric" and srv_loader == "quilt"):
                return 400, {"status": "failure", "error": f"Loader Mismatch: Preset requires '{preset_loader.upper()}', but server is running '{srv_loader.upper()}'."}, []

        loader_tags = get_modrinth_loader_tags(srv_loader)
        import urllib.parse
        loaders_param = urllib.parse.quote(json.dumps(loader_tags))
        versions_param = urllib.parse.quote(json.dumps([srv_mc_ver]))

        project_ids = json.loads(preset["project_ids"])
        if srv_loader in ("fabric", "quilt") and "fabric-api" not in project_ids:
            project_ids.insert(0, "fabric-api")

        files_to_install = []
        incompatible = []

        # Strict All-or-Nothing Version Pre-check
        for p_id in project_ids:
            v_url = f"https://api.modrinth.com/v2/project/{p_id}/version?loaders={loaders_param}&game_versions={versions_param}"
            try:
                m_versions = http_get_json(v_url)
                if not m_versions:
                    incompatible.append(p_id)
                else:
                    latest = m_versions[0]
                    canonical_id = latest.get("project_id", p_id)
                    primary_file = next((f for f in latest["files"] if f.get("primary")), latest["files"][0])
                    files_to_install.append({
                        "canonical_id": canonical_id, "slug": p_id, "version_id": latest["id"],
                        "url": primary_file["url"], "filename": primary_file["filename"]
                    })
            except Exception as e:
                incompatible.append(f"{p_id} ({str(e)})")

        if incompatible:
            return 400, {"status": "failure", "error": f"Preset installation aborted! No compatible build found for Minecraft {srv_mc_ver} on {srv_loader}: {', '.join(incompatible)}"}, []

        for item in files_to_install:
            await query_daemon("install_addon", {
                "name": srv_id, "project_id": item["canonical_id"], "slug": item["slug"],
                "version_id": item["version_id"], "file_url": item["url"], "file_name": item["filename"]
            })

        return 200, {"status": "success", "message": f"Applied preset '{preset['name']}'! Installed {len(files_to_install)} addons for {srv_mc_ver}."}, []

    # 9. ADDONS & MARKETPLACE
    elif method == "GET" and path == "/api/addons/installed":
        res = await query_daemon("get_installed_addons", {"name": srv_id})
        return 200, res, []

    elif method == "POST" and path == "/api/addons/uninstall":
        res = await query_daemon("uninstall_addon", {"name": srv_id, "project_id": body.get("project_id")})
        return 200, res, []

    elif method == "POST" and path == "/api/addons/check_updates":
        res = await query_daemon("get_installed_addons", {"name": srv_id})
        installed = res.get("installed", {})
        if not installed: return 200, {"status": "success", "updates": []}, []

        srv_row = conn.execute("SELECT loader, minecraftversion FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id)).fetchone()
        srv_loader = srv_row["loader"] if srv_row else "paper"
        srv_mc_ver = srv_row["minecraftversion"] if srv_row else "1.20.4"
        loader_tags = get_modrinth_loader_tags(srv_loader)

        import urllib.parse
        updates = []
        for p_id, item in installed.items():
            curr_v = item.get("version_id")
            v_url = f"https://api.modrinth.com/v2/project/{p_id}/version?loaders={urllib.parse.quote(json.dumps(loader_tags))}&game_versions={urllib.parse.quote(json.dumps([srv_mc_ver]))}"
            try:
                m_versions = http_get_json(v_url)
                if m_versions and m_versions[0]["id"] != curr_v:
                    updates.append({
                        "project_id": p_id, "current_version_id": curr_v,
                        "new_version_id": m_versions[0]["id"], "new_version_name": m_versions[0]["name"],
                        "file_name": m_versions[0]["files"][0]["filename"]
                    })
            except Exception: pass

        return 200, {"status": "success", "updates": updates}, []

    elif method == "GET" and path == "/api/addons/search":
        query_str = query.get("q", [""])[0]
        loader = query.get("loader", ["paper"])[0]
        mc_ver = query.get("version", [""])[0]
        loader_tags = get_modrinth_loader_tags(loader)

        import urllib.parse
        facets = [
            [f"categories:{tag}" for tag in loader_tags],
            ["server_side:required", "server_side:optional"]
        ]
        if mc_ver: facets.append([f"versions:{mc_ver}"])

        url = f"https://api.modrinth.com/v2/search?query={urllib.parse.quote(query_str)}&facets={urllib.parse.quote(json.dumps(facets))}&limit=25"
        try:
            results = http_get_json(url)
            filtered_hits = []
            for hit in results.get("hits", []):
                server_env = hit.get("server_side", "")
                client_env = hit.get("client_side", "")
                project_type = hit.get("project_type", "")
                categories = hit.get("categories", [])

                if server_env == "unsupported": continue

                is_plugin = (project_type == "plugin") or any(c in categories for c in ["spigot", "paper", "bukkit", "folia", "velocity", "waterfall", "bungeecord"])
                if is_plugin or client_env in ("optional", "unsupported", ""):
                    env_type = "SERVER_ONLY"
                elif client_env == "required":
                    env_type = "SERVER_AND_CLIENT"
                else:
                    env_type = "SERVER_ONLY"

                hit["env_type"] = env_type
                filtered_hits.append(hit)

            return 200, {"status": "success", "hits": filtered_hits}, []
        except Exception as e:
            return 500, {"status": "failure", "error": f"Search failed: {str(e)}"}, []

    elif method == "POST" and path == "/api/addons/install":
        project_id = body.get("project_id")
        srv_row = conn.execute("SELECT loader, minecraftversion FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id)).fetchone()
        if not srv_row: return 400, {"status": "failure", "error": "Server not found."}, []

        loader_tags = get_modrinth_loader_tags(srv_row["loader"])
        import urllib.parse
        versions_url = f"https://api.modrinth.com/v2/project/{project_id}/version?loaders={urllib.parse.quote(json.dumps(loader_tags))}&game_versions={urllib.parse.quote(json.dumps([srv_row['minecraftversion']]))}"
        try:
            versions = http_get_json(versions_url)
            if not versions:
                versions = http_get_json(f"https://api.modrinth.com/v2/project/{project_id}/version?loaders={urllib.parse.quote(json.dumps(loader_tags))}")

            if not versions: return 400, {"status": "failure", "error": "No compatible build found."}, []

            latest_version = versions[0]
            canonical_id = latest_version.get("project_id", project_id)
            primary_file = next((f for f in latest_version["files"] if f.get("primary")), latest_version["files"][0])

            res = await query_daemon("install_addon", {
                "name": srv_id, "project_id": canonical_id, "slug": project_id,
                "version_id": latest_version["id"], "file_url": primary_file["url"],
                "file_name": primary_file["filename"]
            })
            return 200, res, []
        except Exception as e:
            return 500, {"status": "failure", "error": f"Installation failed: {str(e)}"}, []

    return 404, {"status": "failure", "error": "Endpoint not found."}, []


async def handle_client(reader, writer):
    try:
        req_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
        if not req_line: return
        parts = req_line.decode('utf-8', errors='ignore').strip().split()
        if len(parts) < 2: return

        method, raw_path = parts[0], parts[1]
        headers = {}
        while True:
            hline = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not hline or hline in (b'\r\n', b'\n'): break
            line_str = hline.decode('utf-8', errors='ignore').strip()
            if ':' in line_str:
                k, v = line_str.split(':', 1); headers[k.strip().lower()] = v.strip()

        peer_ip = writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else "127.0.0.1"
        real_client_ip = get_real_client_ip(headers, peer_ip)

        parsed_url = urlparse(raw_path)
        parsed_path = parsed_url.path; parsed_query = parse_qs(parsed_url.query)

        security_headers = [
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: SAMEORIGIN",
            "Referrer-Policy: strict-origin-when-cross-origin",
            "Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ]

        # 1. PWA STATIC ENDPOINTS
        if method == "GET" and parsed_path == "/manifest.json":
            payload = json.dumps(PWA_MANIFEST).encode('utf-8')
            hdr = f"HTTP/1.1 200 OK\r\nContent-Type: application/manifest+json\r\nContent-Length: {len(payload)}\r\n"
            for sh in security_headers: hdr += f"{sh}\r\n"
            hdr += "\r\n"
            writer.write(hdr.encode('utf-8') + payload)
            await writer.drain()
            return

        if method == "GET" and parsed_path == "/sw.js":
            payload = SERVICE_WORKER_SCRIPT.strip().encode('utf-8')
            hdr = f"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {len(payload)}\r\n"
            for sh in security_headers: hdr += f"{sh}\r\n"
            hdr += "\r\n"
            writer.write(hdr.encode('utf-8') + payload)
            await writer.drain()
            return

        # 2. REAL-TIME CONTINUOUS CONSOLE STREAM (MUST BE ABOVE REST API ROUTER)
        if parsed_path == "/api/servers/console/stream":
            srv_id = parsed_query.get("id", [""])[0] or parsed_query.get("name", [""])[0]
            if not srv_id:
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

            sse_headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache, no-transform\r\n"
                "Connection: keep-alive\r\n"
                "X-Accel-Buffering: no\r\n"
                "Access-Control-Allow-Origin: *\r\n\r\n"
            )
            writer.write(sse_headers.encode('utf-8'))
            await writer.drain()

            d_reader, d_writer = None, None
            try:
                if IS_WINDOWS: d_reader, d_writer = await asyncio.open_connection('127.0.0.1', TCP_PORT)
                else: d_reader, d_writer = await asyncio.open_unix_connection(str(SOCKET_PATH))

                # Send stream action to daemon
                d_writer.write(json.dumps({"action": "stream_console", "params": {"name": srv_id}}).encode('utf-8') + b"\n")
                await d_writer.drain()

                # Read initial history dump from daemon
                first_line = await d_reader.readline()
                if first_line:
                    data = json.loads(first_line.decode('utf-8'))
                    init_payload = f"data: {json.dumps({'type': 'init', 'logs': data.get('logs', [])})}\n\n"
                    writer.write(init_payload.encode('utf-8'))
                    await writer.drain()

                # Stream incoming log lines continuously with 15s keepalive ping
                while True:
                    try:
                        line_bytes = await asyncio.wait_for(d_reader.readline(), timeout=15.0)
                        if not line_bytes: break
                        line_data = json.loads(line_bytes.decode('utf-8'))
                        chunk = f"data: {json.dumps({'type': 'line', 'line': line_data.get('line', '')})}\n\n"
                        writer.write(chunk.encode('utf-8'))
                        await writer.drain()
                    except asyncio.TimeoutError:
                        writer.write(b": keepalive\n\n")
                        await writer.drain()

            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, asyncio.CancelledError):
                pass
            finally:
                if d_writer:
                    try: d_writer.close(); await d_writer.wait_closed()
                    except Exception: pass
            return

        # 3. REST API ROUTER
        if parsed_path.startswith("/api/"):
            content_length = int(headers.get("content-length", 0))
            body_bytes = b""
            if content_length > 0 and content_length <= MAX_FILE_SIZE:
                body_bytes = await asyncio.wait_for(reader.readexactly(content_length), timeout=10.0)

            body_json = {}
            if body_bytes and headers.get("content-type", "").startswith("application/json"):
                try: body_json = json.loads(body_bytes.decode('utf-8'))
                except Exception: pass

            status_code, resp_data, extra_hdrs = await handle_api(method, parsed_path, parsed_query, body_json, headers, body_bytes)

            if isinstance(resp_data, dict) and "_raw_binary" in resp_data:
                raw_bytes = resp_data["_raw_binary"]
                hdr_str = f"HTTP/1.1 {status_code} OK\r\n"
                for h in resp_data.get("headers", []): hdr_str += f"{h}\r\n"
                for sh in security_headers: hdr_str += f"{sh}\r\n"
                hdr_str += "\r\n"
                writer.write(hdr_str.encode('utf-8') + raw_bytes)
                await writer.drain()
                return

            payload = json.dumps(resp_data).encode('utf-8')
            hdr_str = f"HTTP/1.1 {status_code} OK\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
            for h in extra_hdrs: hdr_str += f"{h}\r\n"
            for sh in security_headers: hdr_str += f"{sh}\r\n"
            hdr_str += "\r\n"

            writer.write(hdr_str.encode('utf-8') + payload)
            await writer.drain()
            return

        # 4. STATIC WEBPAGE SERVING
        if method == "GET":
            relative_path = parsed_path.lstrip("/")
            target = (WEBPAGE_PATH / relative_path).resolve()
            if relative_path and target.exists() and target.is_file() and target.is_relative_to(WEBPAGE_PATH):
                file_to_serve = target
            else:
                file_to_serve = (WEBPAGE_PATH / "main.html").resolve()

            if not file_to_serve.exists() or not file_to_serve.is_file():
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\n404 Not Found")
                await writer.drain(); return

            file_size = file_to_serve.stat().st_size
            ctype, _ = mimetypes.guess_type(str(file_to_serve))
            if not ctype: ctype = "text/html; charset=utf-8" if str(file_to_serve).endswith(".html") else "application/octet-stream"

            headers_str = f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {file_size}\r\nCache-Control: no-cache, no-store, must-revalidate\r\n"
            for sh in security_headers: headers_str += f"{sh}\r\n"
            headers_str += "\r\n"

            writer.write(headers_str.encode('utf-8'))
            await writer.drain()

            with open(file_to_serve, "rb") as f:
                while chunk := f.read(8192): writer.write(chunk)
            await writer.drain()

    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, asyncio.CancelledError): pass
    finally:
        try: writer.close(); await writer.drain()
        except Exception: pass

async def main(port=5001):
    WEBPAGE_PATH.mkdir(parents=True, exist_ok=True)
    get_db()
    asyncio.create_task(purge_expired_sessions_loop())
    server = await asyncio.start_server(handle_client, '127.0.0.1', port)
    print(f"[AnvilWeb] Production Gateway running at http://127.0.0.1:{port}...", flush=True)
    async with server: await server.serve_forever()


if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n[AnvilWeb] Stopped.")