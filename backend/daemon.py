#!/usr/bin/env python3
"""
AnvilServerHosting - Hardened Daemon Engine (backend/daemon.py)
Features: Recursive Process Tree CPU & Memory Measurement (/proc),
Container PID Inspection, Storage Auditing, and Addon Manifest Management.
"""

import os
import sys
import re
import json
import sqlite3
import signal
import time
import asyncio
import subprocess
import shutil
import urllib.request
from pathlib import Path
import socket



try:
    import fcntl
    def lock_file_ex(fd): fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    def lock_file_un(fd): fcntl.flock(fd, fcntl.LOCK_UN)
except ImportError:
    import msvcrt
    def lock_file_ex(fd):
        try: msvcrt.locking(fd.fileno(), msvcrt.LK_NBLCK, 1)
        except Exception: pass
    def lock_file_un(fd):
        try: msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception: pass

IS_WINDOWS = sys.platform == "win32"
BASE_DIR = Path.home() / ".local" / "share" / "AnvilServerHosting"
RUNTIMES_DIR = BASE_DIR / "mcruntimes"
SERVERS_DIR = BASE_DIR / "mcservers"
DB_PATH = BASE_DIR / "anvil.db"
SOCKET_PATH = BASE_DIR / "anvil.sock"
TCP_PORT = 5002
PODMAN_ROOT_DIR = RUNTIMES_DIR / "containers"

MCSERVERUTIL_PATH = (Path(__file__).parent / "mcserverutil.py").resolve()
SERVER_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
ANSI_ESCAPE_REGEX = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\r')

BLOCKED_CONFIG_KEYS = {
    "server-ip", "server-port", "query.port", "rcon.port",
    "rcon.password", "enable-rcon"
}

HIDDEN_FILES = {".daemon.lock", ".cache", ".git", "server.properties", "libraries", "versions", ".fabric", "cache"}
ALLOWED_FILE_EXTENSIONS = {".txt", ".json", ".yml", ".yaml", ".properties", ".log", ".sk", ".toml", ".conf", ".cfg"}


class HubProxyManager:
    def __init__(self):
        self.process = None
        self.status = "offline"
        self.script_path = (Path(__file__).parent / "hub_proxy.py").resolve()

    async def start(self) -> tuple[bool, str]:
        if self.process and self.process.returncode is None:
            return True, "Hub proxy already running."

        try:
            self.process = await asyncio.create_subprocess_exec(
                sys.executable, str(self.script_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            self.status = "running"
            return True, "Hub proxy started on port 25565."
        except Exception as e:
            self.status = "offline"
            return False, f"Failed to start hub proxy: {str(e)}"

    async def stop(self) -> bool:
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=3.0)
            except Exception:
                self.process.kill()
            self.process = None
        self.status = "offline"
        return True


hub_manager = HubProxyManager()

def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_REGEX.sub('', text)


def find_free_port(start_range: int = 25600, end_range: int = 29999) -> int:
    """Finds an available local TCP port for an instance."""
    for port in range(start_range, end_range):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                return port
            except OSError:
                continue
    # Fallback to OS-assigned ephemeral port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def sanitize_log_line(text: str) -> str:
    if not text: return text
    text = text.replace(str(BASE_DIR), "~/AnvilServerHosting")
    text = text.replace(str(Path.home()), "~")
    text = re.sub(r'/home/[^/\s]+', '~', text)
    return strip_ansi(text)


def validate_server_id(server_id: str) -> str:
    if not server_id or not SERVER_NAME_REGEX.match(server_id):
        raise ValueError(f"Invalid server identifier '{server_id}'.")
    return server_id


def safe_resolve_path(server_dir: Path, rel_path: str) -> Path:
    clean_rel = rel_path.lstrip("/\\") if rel_path else ""
    target = (server_dir / clean_rel).resolve()
    if not target.is_relative_to(server_dir.resolve()):
        raise PermissionError("Path traversal attack detected.")
    return target


def is_hidden_or_protected(item: Path) -> bool:
    name = item.name.lower()
    return name in HIDDEN_FILES or name.startswith(".lock_") or name.startswith(".daemon") or item.is_symlink()


def get_dir_size_mb(path: Path) -> float:
    if not path.exists(): return 0.0
    total_bytes = 0
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = Path(root) / f
            if not fp.is_symlink():
                try: total_bytes += fp.stat().st_size
                except Exception: pass
    return total_bytes / (1024 * 1024)


def get_db():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                display_name TEXT DEFAULT '',
                owner_id TEXT DEFAULT 'system',
                minecraftversion TEXT NOT NULL,
                loader TEXT NOT NULL DEFAULT 'paper',
                backend TEXT NOT NULL DEFAULT 'podman',
                min_ram TEXT DEFAULT '1024M',
                max_ram TEXT DEFAULT '4096M',
                max_cpu TEXT DEFAULT '100',
                view_distance INTEGER DEFAULT 10,
                simulation_distance INTEGER DEFAULT 8,
                java_path TEXT,
                server_dir TEXT,
                created_at TEXT NOT NULL
            )
        """)
        try: conn.execute("ALTER TABLE servers ADD COLUMN display_name TEXT DEFAULT '';")
        except Exception: pass
        try: conn.execute("ALTER TABLE servers ADD COLUMN allocated_port INTEGER DEFAULT 0;")
        except Exception: pass
        try: conn.execute("ALTER TABLE servers ADD COLUMN view_distance INTEGER DEFAULT 10;")
        except Exception: pass
        try: conn.execute("ALTER TABLE servers ADD COLUMN simulation_distance INTEGER DEFAULT 8;")
        except Exception: pass
    return conn


class ServerDaemonManager:
    def __init__(self):
        self.active_servers = {}
        self.subscribers = {}  # server_id -> set of asyncio.Queue

    async def _read_output(self, server_id: str, proc):
        while True:
            line = await proc.stdout.readline()
            if not line: break
            text = sanitize_log_line(line.decode('utf-8', errors='replace').rstrip())
            if text:
                logs = self.active_servers[server_id]["logs"]
                logs.append(text)
                if len(logs) > 2000: self.active_servers[server_id]["logs"] = logs[-1500:]

                # Real-time broadcast to all open web console streams
                for q in list(self.subscribers.get(server_id, set())):
                    try: q.put_nowait(text)
                    except Exception: pass

        await proc.wait()
        lock_fd = self.active_servers[server_id].get("lock_fd")
        if lock_fd:
            try: lock_file_un(lock_fd); lock_fd.close()
            except Exception: pass

        self.active_servers[server_id]["logs"].append(f"[Daemon]: Server stopped.")
        self.active_servers[server_id]["status"] = "offline"
        self.active_servers[server_id]["metrics"] = {"cpu": "0%", "memory": "0 MB"}

        # Broadcast stopped message
        for q in list(self.subscribers.get(server_id, set())):
            try: q.put_nowait("[Daemon]: Server stopped.")
            except Exception: pass

    def get_status(self, server_id: str) -> str:
        if server_id in self.active_servers:
            proc = self.active_servers[server_id]["process"]
            status = self.active_servers[server_id].get("status", "offline")
            if status in ("creating", "starting", "failed") or (proc and proc.returncode is None):
                return status
        return "offline"

    @staticmethod
    def _get_process_tree(main_pid: int) -> set:
        """Recursively resolves all descendant PIDs under main_pid."""
        pids = {main_pid}
        if not Path(f"/proc/{main_pid}").exists():
            return pids

        ppid_to_children = {}
        try:
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    pid = int(entry)
                    try:
                        stat_text = Path(f"/proc/{pid}/stat").read_text()
                        rparen_idx = stat_text.rfind(')')
                        if rparen_idx != -1:
                            after_comm = stat_text[rparen_idx + 1:].split()
                            ppid = int(after_comm[1])
                            ppid_to_children.setdefault(ppid, []).append(pid)
                    except Exception:
                        continue
        except Exception:
            return pids

        stack = [main_pid]
        while stack:
            curr = stack.pop()
            for child in ppid_to_children.get(curr, []):
                if child not in pids:
                    pids.add(child)
                    stack.append(child)
        return pids

    def _find_server_pids(self, server_id: str, main_pid: int, server_dir: Path) -> set:
        """Finds all child Java and container PIDs for a specific server instance."""
        pids = set()

        # 1. Check Podman Container PID if running in container
        container_name = f"mc_{server_id}"
        try:
            res = subprocess.run(
                ["podman", "--root", str(PODMAN_ROOT_DIR.resolve()), "inspect", container_name],
                capture_output=True, text=True, timeout=2
            )
            if res.returncode == 0 and res.stdout:
                data = json.loads(res.stdout)
                if isinstance(data, list) and len(data) > 0:
                    state = data[0].get("State", {})
                    c_pid = state.get("Pid", 0)
                    if state.get("Running") and c_pid > 0:
                        pids.update(self._get_process_tree(c_pid))
        except Exception:
            pass

        # 2. Add process tree under main script PID
        if main_pid:
            pids.update(self._get_process_tree(main_pid))

        # 3. Match any process whose current working directory is server_dir
        if server_dir and server_dir.exists():
            target_cwd = str(server_dir.resolve())
            try:
                for entry in os.listdir('/proc'):
                    if entry.isdigit():
                        pid = int(entry)
                        try:
                            if os.readlink(f"/proc/{pid}/cwd") == target_cwd:
                                pids.update(self._get_process_tree(pid))
                        except Exception:
                            continue
            except Exception:
                pass

        return pids

    async def _monitor_metrics(self, server_id: str, main_pid: int, server_dir: Path):
        """Asynchronously calculates recursive RAM and CPU metrics."""
        page_size = os.sysconf('SC_PAGE_SIZE') if not IS_WINDOWS else 4096
        clk_tck = os.sysconf('SC_CLK_TCK') if not IS_WINDOWS else 100
        num_cpus = os.cpu_count() or 1

        last_proc_time = None
        last_clock_time = None

        while self.get_status(server_id) in ("online", "starting"):
            try:
                all_pids = self._find_server_pids(server_id, main_pid, server_dir)
                total_rss_pages = 0
                total_proc_ticks = 0

                for pid in all_pids:
                    try:
                        statm_text = Path(f"/proc/{pid}/statm").read_text()
                        parts = statm_text.split()
                        if len(parts) >= 2:
                            total_rss_pages += int(parts[1])
                    except Exception:
                        pass

                    try:
                        stat_text = Path(f"/proc/{pid}/stat").read_text()
                        rparen_idx = stat_text.rfind(')')
                        if rparen_idx != -1:
                            after_comm = stat_text[rparen_idx + 1:].split()
                            utime = int(after_comm[11])
                            stime = int(after_comm[12])
                            total_proc_ticks += (utime + stime)
                    except Exception:
                        pass

                rss_mb = (total_rss_pages * page_size) / (1024 * 1024)
                now = asyncio.get_running_loop().time()

                cpu_pct_str = "0.0%"
                if last_proc_time is not None and last_clock_time is not None:
                    dt = now - last_clock_time
                    if dt > 0:
                        d_ticks = (total_proc_ticks - last_proc_time) / clk_tck
                        pct = (d_ticks / dt / num_cpus) * 100
                        cpu_pct_str = f"{max(0.0, pct):.1f}%"

                last_proc_time = total_proc_ticks
                last_clock_time = now

                mem_str = f"{rss_mb / 1024:.2f} GB" if rss_mb >= 1024 else f"{rss_mb:.1f} MB"

                if server_id in self.active_servers:
                    self.active_servers[server_id]["metrics"] = {
                        "cpu": cpu_pct_str,
                        "memory": mem_str
                    }
            except Exception:
                pass

            await asyncio.sleep(2)

        if server_id in self.active_servers:
            self.active_servers[server_id]["metrics"] = {"cpu": "0%", "memory": "0 MB"}

    async def create_server_bg(self, server_id: str, cmd_args: list):
        self.active_servers[server_id] = {
            "process": None, "logs": [f"[Daemon]: Creating instance '{server_id}'..."],
            "status": "creating", "metrics": {"cpu": "0%", "memory": "0 MB"}
        }
        try:
            proc = await asyncio.create_subprocess_exec(*cmd_args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            self.active_servers[server_id]["process"] = proc
            while True:
                line = await proc.stdout.readline()
                if not line: break
                text = sanitize_log_line(line.decode('utf-8', errors='replace').rstrip())
                if text: self.active_servers[server_id]["logs"].append(text)
            await proc.wait()
            if proc.returncode == 0:
                self.active_servers[server_id]["logs"].append(f"[Daemon]: Instance created successfully!")
                self.active_servers[server_id]["status"] = "offline"
            else:
                self.active_servers[server_id]["logs"].append(f"[Daemon]: Creation failed.")
                self.active_servers[server_id]["status"] = "failed"
        except Exception:
            self.active_servers[server_id]["logs"].append("[Daemon]: Creation failed.")
            self.active_servers[server_id]["status"] = "failed"

    async def start_server(self, server_id: str, cmd_args: list, server_dir: Path) -> tuple[bool, str]:
        clean_id = validate_server_id(server_id)
        if self.get_status(clean_id) != "offline":
            return False, f"Server is currently '{self.get_status(clean_id)}'."

        server_dir.mkdir(parents=True, exist_ok=True)
        lock_file_path = server_dir / ".daemon.lock"
        try:
            lock_fd = open(lock_file_path, "w")
            lock_file_ex(lock_fd)
        except OSError:
            return False, "Server is locked by another process."

        allocated_port = find_free_port()
        conn = get_db()
        with conn:
            conn.execute("UPDATE servers SET allocated_port = ? WHERE id = ? OR name = ?", (allocated_port, clean_id, clean_id))

        self.active_servers[clean_id] = {
            "process": None, "logs": [f"[Daemon]: Launching '{clean_id}'..."],
            "status": "starting", "lock_fd": lock_fd, "metrics": {"cpu": "0%", "memory": "0 MB"}
        }

        try:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"

            # Pass dynamic port to mcserverutil
            run_cmd = list(cmd_args) + ["--port", str(allocated_port)]
            if run_cmd and "python" in run_cmd[0] and "-u" not in run_cmd:
                run_cmd.insert(1, "-u")

            proc = await asyncio.create_subprocess_exec(
                *run_cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, cwd=str(server_dir), env=env
            )
            self.active_servers[clean_id]["process"] = proc
            self.active_servers[clean_id]["status"] = "online"

            asyncio.create_task(self._read_output(clean_id, proc))
            asyncio.create_task(self._monitor_metrics(clean_id, proc.pid, server_dir))
            return True, f"Server started on port {allocated_port}."
        except Exception:
            self.active_servers[clean_id]["status"] = "offline"
            lock_file_un(lock_fd); lock_fd.close()
            with conn:
                conn.execute("UPDATE servers SET allocated_port = 0 WHERE id = ? OR name = ?", (clean_id, clean_id))
            return False, "Failed to start server process."

    async def _read_output(self, server_id: str, proc):
        while True:
            line = await proc.stdout.readline()
            if not line: break
            text = sanitize_log_line(line.decode('utf-8', errors='replace').rstrip())
            if text:
                logs = self.active_servers[server_id]["logs"]
                logs.append(text)
                if len(logs) > 2000: self.active_servers[server_id]["logs"] = logs[-1500:]

                for q in list(self.subscribers.get(server_id, set())):
                    try: q.put_nowait(text)
                    except Exception: pass

        await proc.wait()
        lock_fd = self.active_servers[server_id].get("lock_fd")
        if lock_fd:
            try: lock_file_un(lock_fd); lock_fd.close()
            except Exception: pass

        # Release dynamic port in SQLite
        conn = get_db()
        with conn:
            conn.execute("UPDATE servers SET allocated_port = 0 WHERE id = ? OR name = ?", (server_id, server_id))

        self.active_servers[server_id]["logs"].append(f"[Daemon]: Server stopped.")
        self.active_servers[server_id]["status"] = "offline"
        self.active_servers[server_id]["metrics"] = {"cpu": "0%", "memory": "0 MB"}

    async def send_command(self, server_id: str, command: str) -> bool:
        clean_id = validate_server_id(server_id)
        if self.get_status(clean_id) == "online":
            proc = self.active_servers[clean_id]["process"]
            if proc and proc.stdin:
                proc.stdin.write(f"{command}\n".encode('utf-8'))
                await proc.stdin.drain()
                self.active_servers[clean_id]["logs"].append(f"> {command}")
                return True
        return False

    async def stop_server(self, server_id: str) -> bool:
        clean_id = validate_server_id(server_id)
        if self.get_status(clean_id) == "online":
            self.active_servers[clean_id]["status"] = "stopping"
            await self.send_command(clean_id, "stop")
            proc = self.active_servers[clean_id]["process"]
            try: await asyncio.wait_for(proc.wait(), timeout=15.0)
            except asyncio.TimeoutError: proc.terminate()
            return True
        return False

    async def stop_all(self):
        await hub_manager.stop()
        for srv_id in list(self.active_servers.keys()):
            if self.get_status(srv_id) in ("online", "starting"):
                await self.stop_server(srv_id)


daemon_manager = ServerDaemonManager()


async def handle_ipc_client(reader, writer):
    response = {"status": "failure", "error": "Invalid request."}
    is_stream = False
    try:
        data = await reader.readline()
        if not data: return

        request = json.loads(data.decode('utf-8').strip())
        action = request.get("action")
        params = request.get("params", {})
        conn = get_db()

        if action == "list_servers":
            owner_id = params.get("owner_id")
            rows = conn.execute("SELECT * FROM servers WHERE owner_id = ? OR owner_id = 'system' OR owner_id IS NULL OR owner_id = ''", (owner_id,)).fetchall() if owner_id else conn.execute("SELECT * FROM servers").fetchall()
            srv_list = []
            for r in rows:
                srv_id = r["id"]
                display_name = r["display_name"] or r["name"]
                status = daemon_manager.get_status(srv_id)
                metrics = daemon_manager.active_servers.get(srv_id, {}).get("metrics", {"cpu": "0%", "memory": "0 MB"}) if status == "online" else {"cpu": "0%", "memory": "0 MB"}
                srv_list.append({
                    "id": srv_id, "name": srv_id, "display_name": display_name, "owner_id": r["owner_id"],
                    "status": status, "loader": r["loader"], "minecraftversion": r["minecraftversion"],
                    "backend": r["backend"], "metrics": metrics
                })
            response = {"status": "success", "servers": srv_list}
        elif action == "start_hub":
            success, msg = await hub_manager.start()
            response = {"status": "success" if success else "failure", "message": msg, "hub_status": hub_manager.status}

        elif action == "stop_hub":
            await hub_manager.stop()
            response = {"status": "success", "message": "Hub stopped.", "hub_status": "offline"}

        elif action == "get_hub_status":
            response = {"status": "success", "hub_status": hub_manager.status}
        elif action == "get_user_disk_usage":
            owner_id = params.get("owner_id")
            rows = conn.execute("SELECT id FROM servers WHERE owner_id = ?", (owner_id,)).fetchall()
            total_mb = 0.0
            for r in rows:
                total_mb += get_dir_size_mb(SERVERS_DIR / r["id"])
            response = {"status": "success", "used_disk_mb": round(total_mb, 2)}

            
        elif action == "stream_console":
            is_stream = True
            srv_id = validate_server_id(params.get("name"))
            initial_logs = daemon_manager.active_servers.get(srv_id, {}).get("logs", [])

            # Send initial backlog dump
            first_msg = json.dumps({"status": "connected", "logs": initial_logs}) + "\n"
            writer.write(first_msg.encode('utf-8'))
            await writer.drain()

            # Create live queue for real-time lines
            q = asyncio.Queue(maxsize=500)
            daemon_manager.subscribers.setdefault(srv_id, set()).add(q)
            try:
                while True:
                    line = await q.get()
                    writer.write((json.dumps({"line": line}) + "\n").encode('utf-8'))
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                daemon_manager.subscribers.get(srv_id, set()).discard(q)
            return


        elif action == "create_server":
            srv_id = validate_server_id(params.get("id"))
            display_name = params.get("display_name", srv_id)
            owner_id = params.get("owner_id", "system")
            mc_ver = params.get("minecraftversion")
            loader = params.get("loader", "paper")
            backend = params.get("backend", "podman")

            server_dir = SERVERS_DIR / srv_id
            with conn:
                conn.execute("""
                    INSERT OR REPLACE INTO servers (id, name, display_name, owner_id, minecraftversion, loader, backend, min_ram, max_ram, java_path, server_dir, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (srv_id, srv_id, display_name, owner_id, mc_ver, loader, backend, "1024M", "4096M", "", str(server_dir), time.strftime("%Y-%m-%dT%H:%M:%SZ")))

            cmd = [
                sys.executable, str(MCSERVERUTIL_PATH), "--create", srv_id,
                "--minecraftversion", mc_ver, "--loader", loader, "--backend", backend,
                "--owner", owner_id, "--displayname", display_name, "--eula"
            ]
            asyncio.create_task(daemon_manager.create_server_bg(srv_id, cmd))
            response = {"status": "success", "message": f"Server instance creation initiated."}

        elif action == "start_server":
            srv_id = validate_server_id(params.get("name"))
            row = conn.execute("SELECT * FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id)).fetchone()
            if not row: response = {"status": "failure", "error": "Server not found."}
            else:
                cmd = [sys.executable, str(MCSERVERUTIL_PATH), row["id"]]
                success, msg = await daemon_manager.start_server(row["id"], cmd, SERVERS_DIR / row["id"])
                response = {"status": "success" if success else "failure", "message": msg}

        elif action == "stop_server":
            srv_id = validate_server_id(params.get("name"))
            success = await daemon_manager.stop_server(srv_id)
            response = {"status": "success" if success else "failure"}

        elif action == "send_command":
            srv_id = validate_server_id(params.get("name"))
            success = await daemon_manager.send_command(srv_id, params.get("command", ""))
            response = {"status": "success" if success else "failure"}

        elif action == "get_console":
            srv_id = validate_server_id(params.get("name"))
            logs = daemon_manager.active_servers.get(srv_id, {}).get("logs", [])
            response = {"status": "success", "logs": logs, "serverStatus": daemon_manager.get_status(srv_id)}

        elif action == "install_addon":
            import urllib.request
            srv_id = validate_server_id(params.get("name"))
            file_url = params.get("file_url")
            file_name = params.get("file_name")
            project_id = params.get("project_id", "")
            slug = params.get("slug", project_id)
            version_id = params.get("version_id", "")

            srv_row = conn.execute("SELECT loader FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id)).fetchone()
            if not srv_row:
                response = {"status": "failure", "error": "Server not found."}
            else:
                loader = srv_row["loader"].lower()
                server_dir = SERVERS_DIR / srv_id
                target_folder = "plugins" if loader in {"paper", "folia", "travertine", "velocity", "waterfall"} else "mods"
                dest_dir = server_dir / target_folder
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_file = dest_dir / file_name

                cache_dir = server_dir / ".cache"
                cache_dir.mkdir(parents=True, exist_ok=True)
                manifest_file = cache_dir / "addons_manifest.json"

                manifest = {}
                if manifest_file.exists():
                    try: manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                    except Exception: pass

                # Clean up previous version of this addon
                for key in (project_id, slug):
                    if key and key in manifest:
                        old_item = manifest[key]
                        old_file = server_dir / old_item.get("target_folder", target_folder) / old_item.get("file_name", "")
                        if old_file.exists() and old_file != dest_file:
                            try: os.chmod(old_file, 0o644); old_file.unlink()
                            except Exception: pass

                # Download file with identification header
                req = urllib.request.Request(file_url, headers={"User-Agent": "AnvilServerHosting/1.0.0 (contact@anvilserverhosting.local)"})
                with urllib.request.urlopen(req, timeout=30) as resp, open(dest_file, "wb") as f:
                    f.write(resp.read())

                try: os.chmod(dest_file, 0o444)
                except Exception: pass

                # Record in manifest under both ID and slug
                record = {
                    "project_id": project_id,
                    "slug": slug,
                    "version_id": version_id,
                    "file_name": file_name,
                    "target_folder": target_folder,
                    "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                if project_id: manifest[project_id] = record
                if slug and slug != project_id: manifest[slug] = record

                manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                response = {"status": "success", "message": f"Installed '{file_name}' to /{target_folder}!"}

        elif action == "uninstall_addon":
            srv_id = validate_server_id(params.get("name"))
            project_id = params.get("project_id")
            server_dir = SERVERS_DIR / srv_id
            manifest_file = server_dir / ".cache" / "addons_manifest.json"

            if manifest_file.exists():
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
                if project_id in manifest:
                    item = manifest[project_id]
                    file_path = server_dir / item.get("target_folder", "mods") / item.get("file_name", "")
                    if file_path.exists():
                        try: os.chmod(file_path, 0o644); file_path.unlink()
                        except Exception: pass
                    del manifest[project_id]
                    manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                    response = {"status": "success", "message": "Addon uninstalled."}

        elif action == "get_installed_addons":
            srv_id = validate_server_id(params.get("name"))
            manifest_file = SERVERS_DIR / srv_id / ".cache" / "addons_manifest.json"
            installed = {}
            if manifest_file.exists():
                try: installed = json.loads(manifest_file.read_text(encoding="utf-8"))
                except Exception: pass
            response = {"status": "success", "installed": installed}
        elif action == "delete_server":
            srv_id = validate_server_id(params.get("name"))

            # 1. Stop the instance if it is currently running
            if daemon_manager.get_status(srv_id) in ("online", "starting"):
                await daemon_manager.stop_server(srv_id)

            # 2. Delete database entry
            with conn:
                conn.execute("DELETE FROM servers WHERE id = ? OR name = ?", (srv_id, srv_id))

            # 3. Clean up read-only file locks and remove directory from disk
            server_dir = SERVERS_DIR / srv_id
            if server_dir.exists():
                for root, dirs, files in os.walk(server_dir):
                    for f in files:
                        try: os.chmod(os.path.join(root, f), 0o644)
                        except Exception: pass
                shutil.rmtree(server_dir, ignore_errors=True)

            response = {"status": "success", "message": f"Instance '{srv_id}' permanently deleted."}

            
        elif action == "list_files":
            srv_id = validate_server_id(params.get("name"))
            target_path = safe_resolve_path(SERVERS_DIR / srv_id, params.get("path", ""))

            if is_hidden_or_protected(target_path):
                response = {"status": "failure", "error": "Access Denied."}
            elif not target_path.exists():
                response = {"status": "failure", "error": "Path does not exist."}
            elif target_path.is_dir():
                items = []
                for item in target_path.iterdir():
                    if is_hidden_or_protected(item): continue
                    items.append({
                        "name": item.name, "is_dir": item.is_dir(),
                        "size": item.stat().st_size if item.is_file() else 0
                    })
                response = {"status": "success", "type": "dir", "items": items}
            else:
                if target_path.suffix.lower() not in ALLOWED_FILE_EXTENSIONS:
                    response = {"status": "failure", "error": "Cannot edit binary file."}
                else:
                    content = target_path.read_text(encoding="utf-8", errors="ignore")
                    response = {"status": "success", "type": "file", "content": content}

        elif action == "save_file":
            srv_id = validate_server_id(params.get("name"))
            target_path = safe_resolve_path(SERVERS_DIR / srv_id, params.get("path", ""))
            if is_hidden_or_protected(target_path) or target_path.suffix.lower() not in ALLOWED_FILE_EXTENSIONS:
                response = {"status": "failure", "error": "Access Denied."}
            else:
                target_path.write_text(params.get("content", ""), encoding="utf-8")
                response = {"status": "success", "message": "File saved."}

        elif action == "delete_file":
            srv_id = validate_server_id(params.get("name"))
            target_path = safe_resolve_path(SERVERS_DIR / srv_id, params.get("path", ""))
            if is_hidden_or_protected(target_path):
                response = {"status": "failure", "error": "Access Denied."}
            else:
                if target_path.is_dir(): shutil.rmtree(target_path)
                elif target_path.is_file(): target_path.unlink()
                response = {"status": "success", "message": "Deleted."}

        elif action == "create_folder":
            srv_id = validate_server_id(params.get("name"))
            target_path = safe_resolve_path(SERVERS_DIR / srv_id, params.get("path", ""))
            target_path.mkdir(parents=True, exist_ok=True)
            response = {"status": "success", "message": "Folder created."}

        elif action == "get_config":
            srv_id = validate_server_id(params.get("name"))
            props_file = (SERVERS_DIR / srv_id) / "server.properties"
            props = {}
            if props_file.exists():
                for line in props_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1); props[k.strip()] = v.strip()
            response = {"status": "success", "properties": props, "blocked_keys": list(BLOCKED_CONFIG_KEYS)}

        elif action == "save_config":
            srv_id = validate_server_id(params.get("name"))
            props_file = (SERVERS_DIR / srv_id) / "server.properties"
            updates = params.get("properties", {})

            current = {}
            if props_file.exists():
                for line in props_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1); current[k.strip()] = v.strip()

            for k, v in updates.items():
                if k not in BLOCKED_CONFIG_KEYS:
                    current[k] = str(v)

            lines = ["#Minecraft server properties\n#Updated by AnvilServerHosting Config Engine\n"]
            for k, v in current.items(): lines.append(f"{k}={v}\n")
            props_file.write_text("".join(lines), encoding="utf-8")
            response = {"status": "success", "message": "Properties saved."}

    except Exception as e:
        response = {"status": "failure", "error": f"Request failed: {str(e)}"}

    if not is_stream:
        try:
            writer.write(json.dumps(response).encode('utf-8') + b"\n")
            await writer.drain()
        except Exception: pass
        finally:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass




async def run_daemon():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    SERVERS_DIR.mkdir(parents=True, exist_ok=True)
    get_db()

    if IS_WINDOWS:
        server = await asyncio.start_server(handle_ipc_client, '127.0.0.1', TCP_PORT)
        print(f"[AnvilDaemon] TCP Daemon running on 127.0.0.1:{TCP_PORT}", flush=True)
    else:
        if SOCKET_PATH.exists(): SOCKET_PATH.unlink()
        server = await asyncio.start_unix_server(handle_ipc_client, path=str(SOCKET_PATH))
        os.chmod(SOCKET_PATH, 0o600)
        print(f"[AnvilDaemon] UNIX Socket Daemon running at {SOCKET_PATH}", flush=True)

    try: await server.serve_forever()
    except asyncio.CancelledError: pass
    finally:
        await daemon_manager.stop_all()
        if not IS_WINDOWS and SOCKET_PATH.exists(): SOCKET_PATH.unlink()
        print("[AnvilDaemon] Daemon shut down cleanly.", flush=True)


if __name__ == "__main__":
    try: asyncio.run(run_daemon())
    except KeyboardInterrupt: print("\n[AnvilDaemon] Exiting.", flush=True)