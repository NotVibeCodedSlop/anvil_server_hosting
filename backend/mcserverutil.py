#!/usr/bin/env python3
"""
AnvilServerHosting - Minecraft Server Management Engine (mcserverutil.py)
FULL UNTRUNCATED BACKEND ENGINE
Features: SQLite (anvil.db), Atomic Download Locks, Podman Direct Fallback,
Strict Server Name Validation, Full Runtime Loaders (Fabric, NeoForge, Quilt, Paper),
Backup, Restore, Duplicate, Modify, Remove, and Rooted Backends.
"""

import os
import sys
import re
import json
import fcntl
import sqlite3
import shutil
import zipfile
import tarfile
import argparse
import tempfile
import hashlib
import datetime
import platform
import subprocess
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path

# CONFIGURATION
APP_NAME = "AnvilServerHosting"
BASE_DIR = Path.home() / ".local" / "share" / APP_NAME
RUNTIMES_DIR = BASE_DIR / "mcruntimes"
SERVERS_DIR = BASE_DIR / "mcservers"
DB_PATH = BASE_DIR / "anvil.db"

PAPER_SPINOFFS = {"paper", "folia", "travertine", "velocity", "waterfall"}
SUPPORTED_LOADERS = {"vanilla", "fabric", "neoforge", "quilt"}.union(PAPER_SPINOFFS)
SUPPORTED_BACKENDS = {"direct", "podman", "rooted_user", "rooted_podman"}

USER_AGENT = f"{APP_NAME}/1.0 (https://github.com/AnvilServerHosting)"
PODMAN_BASE_IMAGE = "docker.io/library/debian:bookworm-slim"

# STRICT SERVER NAME REGEX REQUIREMENT: Only a-z, A-Z, 0-9, -, _
SERVER_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')


def validate_server_name(name: str) -> str:
    """Strictly validates server names to allow only a-z, A-Z, 0-9, -, _."""
    if not name or not SERVER_NAME_REGEX.match(name):
        raise ValueError(
            f"Invalid server name '{name}'. Names MUST ONLY contain characters a-z, A-Z, 0-9, '-' and '_'."
        )
    return name


def get_db():
    """Initializes and connects to the central SQLite database in WAL mode."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                display_name TEXT DEFAULT '',
                owner_id TEXT DEFAULT 'system',
                minecraftversion TEXT NOT NULL,
                loader TEXT NOT NULL DEFAULT 'paper',
                backend TEXT NOT NULL DEFAULT 'podman',
                min_ram TEXT DEFAULT '1024M',
                max_ram TEXT DEFAULT '4096M',
                java_path TEXT,
                server_dir TEXT,
                created_at TEXT NOT NULL
            )
        """)
        try: conn.execute("ALTER TABLE servers ADD COLUMN owner_id TEXT DEFAULT 'system';")
        except Exception: pass
        try: conn.execute("ALTER TABLE servers ADD COLUMN display_name TEXT DEFAULT '';")
        except Exception: pass
    return conn


def log(msg: str):
    print(f"[{APP_NAME}] {msg}")


def log_error(msg: str):
    print(f"[{APP_NAME}] ERROR: {msg}", file=sys.stderr)


def http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get_xml(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode("utf-8")


def http_post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ==============================================================================
# ATOMIC DOWNLOAD LOCKING MECHANISM
# ==============================================================================
def download_file(url: str, dest_path: Path, expected_hash: str = None, hash_algo: str = "sha1") -> bool:
    """
    Downloads file with atomic file locking (fcntl.flock).
    If another process is downloading the same file, this process waits.
    Once unlocked, it verifies hash/file existence before returning True.
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file_path = dest_path.parent / f".lock_{dest_path.name}"

    with open(lock_file_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            if dest_path.exists():
                if expected_hash:
                    hasher = hashlib.new(hash_algo)
                    with open(dest_path, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            hasher.update(chunk)
                    if hasher.hexdigest().lower() == expected_hash.lower():
                        log(f"File '{dest_path.name}' already cached and hash verified. Skipping download.")
                        return True
                else:
                    log(f"File '{dest_path.name}' already cached. Skipping download.")
                    return True

            log(f"Downloading {url} -> {dest_path.name}...")
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            tmp_dest = dest_path.with_suffix(dest_path.suffix + ".tmp")

            with urllib.request.urlopen(req) as resp, open(tmp_dest, "wb") as out_file:
                shutil.copyfileobj(resp, out_file)

            if expected_hash:
                hasher = hashlib.new(hash_algo)
                with open(tmp_dest, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        hasher.update(chunk)
                calc_hash = hasher.hexdigest().lower()
                if calc_hash != expected_hash.lower():
                    tmp_dest.unlink(missing_ok=True)
                    raise ValueError(f"Hash mismatch for {dest_path.name}: expected {expected_hash}, got {calc_hash}")

            tmp_dest.replace(dest_path)
            log(f"Successfully downloaded '{dest_path.name}'.")
            return True

        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def ensure_symlink(target_path: Path, link_path: Path):
    if link_path.is_symlink() or link_path.exists():
        if link_path.is_dir() and not link_path.is_symlink():
            shutil.rmtree(link_path)
        else:
            link_path.unlink()
    link_path.symlink_to(target_path)


def merge_directories(src_dir: Path, dst_dir: Path):
    dst_dir.mkdir(parents=True, exist_ok=True)
    for item in src_dir.iterdir():
        target = dst_dir / item.name
        if item.is_dir():
            merge_directories(item, target)
        else:
            shutil.copy2(item, target)


def resolve_server_dir(target: str, custom_dir: str = None) -> Path:
    if custom_dir:
        return Path(custom_dir).resolve()
    if not target:
        return None

    clean_target = validate_server_name(target)
    servers_candidate = SERVERS_DIR / clean_target
    if servers_candidate.exists() or servers_candidate.is_symlink():
        return servers_candidate.resolve()

    return None


def lock_jar_executables_read_only(server_dir: Path):
    """Applies POSIX chmod 444 (Read-Only) sandboxing to JAR files."""
    if sys.platform == "win32":
        return

    server_jar = server_dir / "server.jar"
    if server_jar.exists():
        try:
            os.chmod(server_jar, 0o444)
        except Exception:
            pass

    for folder in ["mods", "plugins"]:
        target_dir = server_dir / folder
        if target_dir.exists():
            for jar_file in target_dir.glob("*.jar"):
                try:
                    os.chmod(jar_file, 0o444)
                except Exception:
                    pass


# AUTOMATIC JAVA DOWNLOADER & MANAGED RUNTIME WITH CONCURRENCY LOCKS
def get_auto_java(major_version: int = 21) -> str:
    java_dir = RUNTIMES_DIR / "java" / f"jdk-{major_version}"
    java_bin = java_dir / "bin" / ("java.exe" if sys.platform == "win32" else "java")

    if java_bin.exists():
        return str(java_bin.resolve())

    lock_file_path = RUNTIMES_DIR / "java" / f".lock_jdk-{major_version}"
    (RUNTIMES_DIR / "java").mkdir(parents=True, exist_ok=True)

    with open(lock_file_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            if java_bin.exists():
                return str(java_bin.resolve())

            log(f"Auto-downloading Eclipse Temurin OpenJDK {major_version} JRE into mcruntimes/java...")
            sys_os = platform.system().lower()
            sys_arch = platform.machine().lower()

            os_key = "linux" if "linux" in sys_os else ("windows" if "win" in sys_os else "mac")
            arch_key = "aarch64" if sys_arch in ("aarch64", "arm64") else "x64"

            url = f"https://api.adoptium.net/v3/binary/latest/{major_version}/ga/{os_key}/{arch_key}/jre/hotspot/normal/eclipse"
            archive_ext = ".zip" if os_key == "windows" else ".tar.gz"

            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_archive = Path(tmp_dir) / f"jdk{major_version}{archive_ext}"
                download_file(url, tmp_archive)

                log("Extracting Java JRE...")
                if archive_ext == ".zip":
                    with zipfile.ZipFile(tmp_archive, "r") as zf:
                        zf.extractall(tmp_dir)
                else:
                    with tarfile.open(tmp_archive, "r:gz") as tf:
                        tf.extractall(tmp_dir)

                extracted_root = None
                for path in Path(tmp_dir).rglob("bin"):
                    if (path / "java").exists() or (path / "java.exe").exists():
                        extracted_root = path.parent
                        break

                if not extracted_root:
                    raise ValueError("Failed to locate extracted Java directory structure.")

                merge_directories(extracted_root, java_dir)

            if sys.platform != "win32" and java_bin.exists():
                os.chmod(java_bin, 0o755)

            log(f"Java {major_version} pre-installed at: {java_bin.resolve()}")
            return str(java_bin.resolve())
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def check_java(java_bin: str = None, required_major_version: int = 21) -> str:
    if java_bin and (shutil.which(java_bin) or Path(java_bin).is_file()):
        return str(Path(java_bin).resolve())

    managed_java_dir = RUNTIMES_DIR / "java" / f"jdk-{required_major_version}"
    managed_java_bin = managed_java_dir / "bin" / ("java.exe" if sys.platform == "win32" else "java")

    if managed_java_bin.exists():
        return str(managed_java_bin.resolve())

    return get_auto_java(required_major_version)


def prepull_podman_image(backend: str):
    if backend in ("podman", "rooted_podman") and shutil.which("podman"):
        podman_root_dir = RUNTIMES_DIR / "containers"
        podman_root_dir.mkdir(parents=True, exist_ok=True)

        check_cmd = ["podman", "--root", str(podman_root_dir.resolve()), "image", "exists", PODMAN_BASE_IMAGE]
        res = subprocess.run(check_cmd, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            log(f"Debian Podman image ({PODMAN_BASE_IMAGE}) already cached locally. Skipping download.")
            return

        log(f"Pre-pulling minimal Debian container image ({PODMAN_BASE_IMAGE})...")
        podman_cmd = ["podman", "--root", str(podman_root_dir.resolve()), "pull", PODMAN_BASE_IMAGE]
        try:
            subprocess.run(podman_cmd, check=False)
            log("Debian container image cached locally inside mcruntimes/containers.")
        except Exception as e:
            log_error(f"Failed to pre-pull Debian Podman image: {e}")


# DOWNLOAD MANAGERS
def get_mojang_version_data(mc_version: str) -> tuple[dict, int]:
    cache_file = RUNTIMES_DIR / "cache" / f"version_data_{mc_version}.json"
    if cache_file.exists():
        try:
            with open(cache_file, "r") as f:
                version_data = json.load(f)
            java_major = version_data.get("javaVersion", {}).get("majorVersion", 21)
            return version_data, java_major
        except Exception:
            pass

    log(f"Fetching Mojang version manifest for Minecraft {mc_version}...")
    manifest = http_get_json("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json")

    version_entry = next((v for v in manifest.get("versions", []) if v["id"] == mc_version), None)
    if not version_entry:
        raise ValueError(f"Minecraft version '{mc_version}' not found in Mojang manifest.")

    version_data = http_get_json(version_entry["url"])
    java_major = version_data.get("javaVersion", {}).get("majorVersion", 21)

    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(cache_file, "w") as f:
            json.dump(version_data, f)
    except Exception:
        pass

    return version_data, java_major


def get_mojang_vanilla_jar(mc_version: str) -> tuple[Path, int]:
    vanilla_jar = RUNTIMES_DIR / "versions" / f"vanilla-{mc_version}.jar"
    cache_mojang_jar = RUNTIMES_DIR / "cache" / f"mojang_{mc_version}.jar"

    version_data, java_major = get_mojang_version_data(mc_version)

    if vanilla_jar.exists() and cache_mojang_jar.exists():
        return vanilla_jar, java_major

    server_info = version_data.get("downloads", {}).get("server")
    if not server_info:
        raise ValueError(f"No server download found for Minecraft version '{mc_version}'.")

    download_file(server_info["url"], vanilla_jar, expected_hash=server_info.get("sha1"), hash_algo="sha1")
    cache_mojang_jar.parent.mkdir(parents=True, exist_ok=True)
    ensure_symlink(vanilla_jar, cache_mojang_jar)
    return vanilla_jar, java_major


def setup_fabric_runtime(mc_version: str, java_bin: str = "java") -> Path:
    fabric_dir = RUNTIMES_DIR / "fabric"
    launch_jar = fabric_dir / "fabric-server-launch.jar"
    version_file = fabric_dir / "loader_version.txt"

    if launch_jar.exists() and version_file.exists():
        return launch_jar

    lock_file_path = RUNTIMES_DIR / ".lock_fabric_builder"
    RUNTIMES_DIR.mkdir(parents=True, exist_ok=True)

    with open(lock_file_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            if launch_jar.exists() and version_file.exists():
                return launch_jar

            log("Building Fabric loader runtime...")
            loaders = http_get_json("https://meta.fabricmc.net/v2/versions/loader")
            latest_loader_ver = loaders[0]["version"]
            installers = http_get_json("https://meta.fabricmc.net/v2/versions/installer")
            installer_url = installers[0]["url"]

            resolved_java = check_java(java_bin)
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                installer_jar = tmp_path / "installer.jar"
                download_file(installer_url, installer_jar)

                cmd = [resolved_java, "-jar", str(installer_jar), "server", "-mcversion", mc_version, "-loader", latest_loader_ver]
                subprocess.run(cmd, cwd=tmp_dir, check=True, stdout=subprocess.DEVNULL)

                tmp_libs = tmp_path / "libraries"
                tmp_launch = tmp_path / "fabric-server-launch.jar"

                if tmp_libs.exists():
                    merge_directories(tmp_libs, RUNTIMES_DIR / "libraries")
                if tmp_launch.exists():
                    fabric_dir.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(tmp_launch), str(launch_jar))

            version_file.write_text(latest_loader_ver)
            return launch_jar
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def setup_quilt_runtime(mc_version: str, java_bin: str = "java") -> Path:
    quilt_dir = RUNTIMES_DIR / "quilt"
    launch_jar = quilt_dir / "quilt-server-launch.jar"
    version_file = quilt_dir / "loader_version.txt"

    if launch_jar.exists() and version_file.exists():
        return launch_jar

    lock_file_path = RUNTIMES_DIR / ".lock_quilt_builder"
    RUNTIMES_DIR.mkdir(parents=True, exist_ok=True)

    with open(lock_file_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            if launch_jar.exists() and version_file.exists():
                return launch_jar

            log("Building QuiltMC loader runtime...")
            loaders = ET.fromstring(http_get_xml("https://maven.quiltmc.org/repository/release/org/quiltmc/quilt-installer/maven-metadata.xml"))
            latest_loader_ver = loaders.find(".//versioning/latest").text
            installer_url = "https://quiltmc.org/api/v1/download-latest-installer/java-universal"
            resolved_java = check_java(java_bin)

            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                installer_jar = tmp_path / "installer.jar"
                download_file(installer_url, installer_jar)

                cmd = [resolved_java, "-jar", str(installer_jar), "install", "server", mc_version]
                subprocess.run(cmd, cwd=tmp_dir, check=True, stdout=subprocess.DEVNULL)

                tmp_libs = tmp_path / "libraries"
                tmp_launch = tmp_path / "quilt-server-launch.jar"

                if tmp_libs.exists():
                    merge_directories(tmp_libs, RUNTIMES_DIR / "libraries")
                if tmp_launch.exists():
                    quilt_dir.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(tmp_launch), str(launch_jar))

            version_file.write_text(latest_loader_ver)
            return launch_jar
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def get_paper_spinoff_jar(loader: str, mc_version: str) -> Path:
    jar_path = RUNTIMES_DIR / "versions" / f"{loader}-{mc_version}.jar"
    if jar_path.exists():
        return jar_path

    graphql_query = {
        "operationName": "VersionBuilds",
        "query": """query VersionBuilds($projectKey: String!, $versionKey: String!, $after: String) {
            project(key: $projectKey) {
                version(key: $versionKey) {
                    builds(first: 25, after: $after, orderBy: {direction: DESC}) {
                        edges {
                            node {
                                downloads {
                                    url
                                    checksums { sha256 }
                                }
                            }
                        }
                    }
                }
            }
        }""",
        "variables": {"after": None, "projectKey": loader, "versionKey": mc_version}
    }

    resp = http_post_json("https://fill.papermc.io/graphql", graphql_query)
    edges = resp["data"]["project"]["version"]["builds"]["edges"]
    if not edges:
        raise ValueError(f"No builds found for '{loader}' version '{mc_version}'.")
    download = edges[0]["node"]["downloads"][0]
    download_url = download["url"]
    sha256 = download.get("checksums", {}).get("sha256")

    download_file(download_url, jar_path, expected_hash=sha256, hash_algo="sha256")
    return jar_path


def setup_neoforge_runtime(mc_version: str, java_bin: str, server_dir: Path):
    neoforge_lib_root = RUNTIMES_DIR / "libraries" / "net" / "neoforged" / "neoforge"
    prefix = mc_version[2:] if mc_version.startswith("1.") else mc_version
    if not prefix.endswith("."):
        prefix = prefix + "."

    if not (neoforge_lib_root.exists() and any(d.name.startswith(prefix) for d in neoforge_lib_root.iterdir() if d.is_dir())):
        vanilla_jar, _ = get_mojang_vanilla_jar(mc_version)
        xml_data = http_get_xml("https://maven.neoforged.net/releases/net/neoforged/neoforge/maven-metadata.xml")
        root = ET.fromstring(xml_data)

        versions = [v.text for v in root.findall(".//version") if v.text]
        matching = [v for v in versions if v.startswith(prefix)]
        if not matching:
            raise ValueError(f"No NeoForge version found for Minecraft {mc_version}.")

        latest_neoforge_ver = matching[-1]
        installer_url = f"https://maven.neoforged.net/releases/net/neoforged/neoforge/{latest_neoforge_ver}/neoforge-{latest_neoforge_ver}-installer.jar"
        resolved_java = check_java(java_bin)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            installer_jar = tmp_path / "installer.jar"
            download_file(installer_url, installer_jar)

            srv_lib_dir = tmp_path / "libraries" / "net" / "minecraft" / "server" / mc_version
            srv_lib_dir.mkdir(parents=True, exist_ok=True)
            ensure_symlink(vanilla_jar, srv_lib_dir / f"server-{mc_version}.jar")
            ensure_symlink(vanilla_jar, srv_lib_dir / f"server-{mc_version}-bundled.jar")
            ensure_symlink(vanilla_jar, tmp_path / "server.jar")

            cmd = [resolved_java, "-jar", str(installer_jar), "--installServer"]
            subprocess.run(cmd, cwd=tmp_path, check=True)

            tmp_libs = tmp_path / "libraries"
            if tmp_libs.exists():
                merge_directories(tmp_libs, RUNTIMES_DIR / "libraries")

    if neoforge_lib_root.exists():
        for ver_dir in neoforge_lib_root.iterdir():
            if ver_dir.is_dir() and ver_dir.name.startswith(prefix):
                for shim_jar in ver_dir.glob("*.jar"):
                    if "installer" not in shim_jar.name:
                        ensure_symlink(shim_jar, server_dir / shim_jar.name)


def initialize_server_files(server_dir: Path, java_bin: str, loader: str, mc_version: str):
    (server_dir / "eula.txt").write_text("eula=false\n")
    jvm_args = [java_bin]

    if loader in ("forge", "neoforge"):
        user_jvm_file = server_dir / "user_jvm_args.txt"
        if not user_jvm_file.exists():
            user_jvm_file.write_text("# Custom JVM Arguments\n")

        args_name = "win_args.txt" if sys.platform == "win32" else "unix_args.txt"
        target_group = "minecraftforge" if loader == "forge" else "neoforged"
        forge_lib_dir = server_dir / "libraries" / "net" / target_group

        args_file = None
        if forge_lib_dir.exists():
            prefix = mc_version[2:] if (loader == "neoforge" and mc_version.startswith("1.")) else mc_version
            found_args = list(forge_lib_dir.glob(f"{prefix}*/{args_name}")) or list(forge_lib_dir.glob(f"*/*/{args_name}"))
            if found_args: args_file = found_args[-1]

        if args_file:
            try:
                content = args_file.read_text(encoding="utf-8", errors="ignore")
                abs_lib_path = str((RUNTIMES_DIR / "libraries").resolve())
                content = content.replace("libraries/", f"{abs_lib_path}/").replace("libraries\\", f"{abs_lib_path}\\")
                parsed_args = [a.strip() for a in content.replace("\r\n", " ").replace("\n", " ").split(" ") if a.strip()]
                jvm_args.extend(parsed_args)
            except Exception:
                rel_args = args_file.relative_to(server_dir)
                jvm_args.append(f"@{rel_args}")
        else:
            jvm_args.extend(["-jar", "server.jar"])

    elif loader in ("quilt", "fabric"):
        launch_jar = RUNTIMES_DIR / loader / f"{loader}-server-launch.jar"
        if launch_jar.exists():
            with zipfile.ZipFile(launch_jar, "r") as zf:
                manifest_str = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
            unwrapped = manifest_str.replace("\r\n ", "").replace("\n ", "").replace("\r\n\t", "").replace("\n\t", "")
            main_class, class_path = None, None
            for line in unwrapped.splitlines():
                if line.startswith("Main-Class:"): main_class = line.split(":", 1)[1].strip()
                elif line.startswith("Class-Path:"): class_path = line.split(":", 1)[1].strip()
            jvm_args.extend(["-cp", ":".join(class_path.split()), main_class])
        else:
            jvm_args.extend(["-jar", "server.jar"])
    else:
        jvm_args.extend(["-jar", "server.jar"])

    jvm_args.append("nogui")
    try:
        subprocess.run(jvm_args, cwd=server_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    except Exception as e:
        log(f"First-pass initialization completed: {e}")


# BACKUP & RESTORE MANAGERS
def backup_server(target: str, custom_dir: str = None):
    clean_target = validate_server_name(target)
    server_dir = resolve_server_dir(clean_target, custom_dir)
    if not server_dir or not server_dir.exists():
        log_error(f"Server '{clean_target}' does not exist.")
        sys.exit(1)

    backups_dir = server_dir / "backups"
    backups_dir.mkdir(exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    zip_path = backups_dir / f"snapshot_{timestamp}.zip"
    skip_dirs = {"backups", "cache", "logs", ".fabric", ".cache"}

    log(f"Creating snapshot for '{server_dir.name}'...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(server_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for file in files:
                if file.endswith(".lock"): continue
                file_path = Path(root) / file
                zipf.write(file_path, file_path.relative_to(server_dir))

    log(f"Backup snapshot created: {zip_path}")


def restore_server(target: str, backup_file: str, custom_dir: str = None):
    clean_target = validate_server_name(target)
    server_dir = resolve_server_dir(clean_target, custom_dir)
    if not server_dir or not server_dir.exists():
        log_error(f"Server '{clean_target}' does not exist.")
        sys.exit(1)

    backup_path = Path(backup_file).resolve()
    if not backup_path.exists():
        backup_path = server_dir / "backups" / backup_file
        if not backup_path.exists():
            log_error(f"Backup file '{backup_file}' not found.")
            sys.exit(1)

    log(f"Restoring '{server_dir.name}' from snapshot: {backup_path.name}...")
    with zipfile.ZipFile(backup_path, "r") as zipf:
        zipf.extractall(server_dir)
    log("Server restored successfully.")


def setup_rooted_user(user_name: str, server_dir: Path):
    if sys.platform == "win32" or os.geteuid() != 0:
        return
    log(f"Ensuring dedicated isolated system user '{user_name}' exists...")
    try:
        subprocess.run(["useradd", "-r", "-m", "-s", "/bin/bash", user_name], stderr=subprocess.DEVNULL)
        subprocess.run(["loginctl", "enable-linger", user_name], stderr=subprocess.DEVNULL)
        subprocess.run(["chown", "-R", f"{user_name}:{user_name}", str(server_dir)], check=True)
    except Exception as e:
        log_error(f"Failed to set up rooted user '{user_name}': {e}")


# ACTIONS
def create_server(name: str, mc_version: str, loader: str = "paper", eula_accepted: bool = False, java_bin: str = None, max_ram: str = "4096M", min_ram: str = "1024M", custom_dir: str = None, backend: str = "podman", owner_id: str = "system", display_name: str = None):
    server_name = validate_server_name(name)
    server_dir = Path(custom_dir).resolve() if custom_dir else SERVERS_DIR / server_name

    if server_dir.exists() and any(server_dir.iterdir()):
        log_error(f"Target directory '{server_dir}' already exists.")
        sys.exit(1)

    loader_norm = (loader.lower() if loader else "paper").strip()
    backend_norm = (backend.lower() if backend else "podman").strip()

    if backend_norm == "podman" and not shutil.which("podman"):
        log("Podman is not installed on this system. Automatically falling back to 'direct' execution backend.")
        backend_norm = "direct"

    for folder in ["libraries", "versions", "cache", "fabric", "neoforge", "java", "containers", "quilt"]:
        (RUNTIMES_DIR / folder).mkdir(parents=True, exist_ok=True)

    vanilla_jar, java_major = get_mojang_vanilla_jar(mc_version)
    resolved_java = check_java(java_bin, required_major_version=java_major)
    prepull_podman_image(backend_norm)

    server_dir.mkdir(parents=True, exist_ok=True)
    (server_dir / ".cache").mkdir(parents=True, exist_ok=True)

    for folder in ["libraries", "versions", "cache"]:
        ensure_symlink(RUNTIMES_DIR / folder, server_dir / folder)

    ensure_symlink(vanilla_jar, server_dir / "server.jar")

    if loader_norm == "vanilla":
        pass
    elif loader_norm == "fabric":
        setup_fabric_runtime(mc_version, resolved_java)
    elif loader_norm == "quilt":
        setup_quilt_runtime(mc_version, resolved_java)
    elif loader_norm in PAPER_SPINOFFS:
        spinoff_jar = get_paper_spinoff_jar(loader_norm, mc_version)
        ensure_symlink(spinoff_jar, server_dir / "server.jar")
    elif loader_norm == "neoforge":
        setup_neoforge_runtime(mc_version, resolved_java, server_dir)

    initialize_server_files(server_dir, resolved_java, loader_norm, mc_version)

    if eula_accepted:
        (server_dir / "eula.txt").write_text("eula=true\n")

    disp_name = display_name or server_name
    conn = get_db()
    with conn:
        conn.execute("""
            INSERT OR REPLACE INTO servers (id, name, display_name, owner_id, minecraftversion, loader, backend, min_ram, max_ram, java_path, server_dir, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            server_name, server_name, disp_name, owner_id or 'system', mc_version, loader_norm, backend_norm,
            min_ram, max_ram, resolved_java, str(server_dir), datetime.datetime.now(datetime.timezone.utc).isoformat()
        ))

    log(f"Successfully created server '{server_name}' at {server_dir}")


def execute_server(srv_row: sqlite3.Row, server_dir: Path, java_override: str = None, max_ram_override: str = None, min_ram_override: str = None, port_override: int = None):
    loader = srv_row["loader"]
    backend = srv_row["backend"]
    server_name = srv_row["name"]
    java_bin = check_java(java_override or srv_row["java_path"])
    max_ram = max_ram_override or srv_row["max_ram"]
    min_ram = min_ram_override or srv_row["min_ram"]
    mc_version = srv_row["minecraftversion"]

    target_port = port_override or srv_row["allocated_port"] or 25565

    # Dynamically inject assigned port into server.properties
    props_file = server_dir / "server.properties"
    if props_file.exists():
        lines = props_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        new_lines = []
        port_found = False
        for line in lines:
            if line.startswith("server-port="):
                new_lines.append(f"server-port={target_port}")
                port_found = True
            else:
                new_lines.append(line)
        if not port_found:
            new_lines.append(f"server-port={target_port}")
        props_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


    if backend in ("podman", "rooted_podman") and not shutil.which("podman"):
        log("Podman missing. Falling back to direct process execution.")
        backend = "direct"

    jvm_args = [java_bin]
    if max_ram: jvm_args.append(f"-Xmx{max_ram}")
    if min_ram: jvm_args.append(f"-Xms{min_ram}")

    if loader in ("forge", "neoforge"):
        target_group = Path("minecraftforge") / "forge" if loader == "forge" else Path("neoforged") / "neoforge"
        forge_lib_dir = server_dir / "libraries" / "net" / target_group
        args_name = "win_args.txt" if sys.platform == "win32" else "unix_args.txt"
        args_file = None
        if forge_lib_dir.exists():
            prefix = mc_version[2:] if (loader == "neoforge" and mc_version.startswith("1.")) else mc_version
            found_args = list(forge_lib_dir.glob(f"{prefix}*/{args_name}")) or list(forge_lib_dir.glob(f"*/*/{args_name}"))
            if found_args: args_file = found_args[-1]

        if args_file:
            content = args_file.read_text(encoding="utf-8", errors="ignore")
            abs_lib_path = str((RUNTIMES_DIR / "libraries").resolve())
            content = content.replace("libraries/", f"{abs_lib_path}/").replace("libraries\\", f"{abs_lib_path}\\")
            parsed_args = [a.strip() for a in content.replace("\r\n", " ").replace("\n", " ").split(" ") if a.strip()]
            jvm_args.extend(parsed_args)
        else:
            jvm_args.extend(["-jar", "server.jar"])

    elif loader in ("fabric", "quilt"):
        launch_jar = RUNTIMES_DIR / loader / f"{loader}-server-launch.jar"
        with zipfile.ZipFile(launch_jar, "r") as zf:
            manifest_str = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
        unwrapped = manifest_str.replace("\r\n ", "").replace("\n ", "").replace("\r\n\t", "").replace("\n\t", "")
        main_class, class_path = None, None
        for line in unwrapped.splitlines():
            if line.startswith("Main-Class:"): main_class = line.split(":", 1)[1].strip()
            elif line.startswith("Class-Path:"): class_path = line.split(":", 1)[1].strip()
        jvm_args.extend(["-cp", ":".join(class_path.split()), main_class])
    else:
        jvm_args.extend(["-jar", "server.jar"])

    jvm_args.append("nogui")
    os.chdir(server_dir)

    if backend == "direct":
        lock_jar_executables_read_only(server_dir)
        subprocess.run(jvm_args)
    elif backend == "rooted_user":
        user_name = f"mc_{server_name.lower()}"
        setup_rooted_user(user_name, server_dir)
        lock_jar_executables_read_only(server_dir)
        subprocess.run(["sudo", "-u", user_name] + jvm_args)
    elif backend in ("podman", "rooted_podman"):
        podman_root_dir = RUNTIMES_DIR / "containers"
        podman_cmd = [
            "podman", "--root", str(podman_root_dir.resolve()),
            "run", "-it", "--rm",
            "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev",
            "--tmpfs", "/var/tmp:rw,nosuid,nodev",
            "--name", f"mc_{server_name}",
            "-v", f"{RUNTIMES_DIR.resolve()}:{RUNTIMES_DIR.resolve()}:ro",
            "-v", f"{server_dir.resolve()}:{server_dir.resolve()}:rw",
            "-w", str(server_dir.resolve()),
            "-p", "25565:25565",
            PODMAN_BASE_IMAGE
        ] + [str(java_bin)] + jvm_args[1:]
        subprocess.run(podman_cmd)


def start_server(target: str, java_override: str = None, max_ram_override: str = None, min_ram_override: str = None, custom_dir: str = None, backend_override: str = None):
    clean_target = validate_server_name(target) if target else None
    conn = get_db()
    row = conn.execute("SELECT * FROM servers WHERE name = ?", (clean_target,)).fetchone()

    if not row:
        log_error(f"Server '{clean_target}' not found in SQLite registry.")
        sys.exit(1)

    server_dir = resolve_server_dir(clean_target, custom_dir or row["server_dir"])
    execute_server(row, server_dir, java_override, max_ram_override, min_ram_override)


def modify_server(target: str, loader: str = None, java_bin: str = None, max_ram: str = None, min_ram: str = None, backend: str = None, custom_dir: str = None):
    clean_target = validate_server_name(target)
    conn = get_db()
    row = conn.execute("SELECT * FROM servers WHERE name = ?", (clean_target,)).fetchone()
    if not row:
        log_error(f"Server '{clean_target}' not found.")
        sys.exit(1)

    new_loader = loader.lower().strip() if loader else row["loader"]
    new_backend = backend.lower().strip() if backend else row["backend"]
    new_max_ram = max_ram if max_ram else row["max_ram"]
    new_min_ram = min_ram if min_ram else row["min_ram"]
    new_java = java_bin if java_bin else row["java_path"]

    with conn:
        conn.execute("""
            UPDATE servers SET loader = ?, backend = ?, max_ram = ?, min_ram = ?, java_path = ?
            WHERE name = ?
        """, (new_loader, new_backend, new_max_ram, new_min_ram, new_java, clean_target))

    log(f"Successfully updated configuration for server '{clean_target}'.")


def remove_server(target: str, custom_dir: str = None):
    clean_target = validate_server_name(target)
    conn = get_db()
    with conn:
        conn.execute("DELETE FROM servers WHERE name = ?", (clean_target,))

    server_dir = resolve_server_dir(clean_target, custom_dir)
    if server_dir and server_dir.exists():
        shutil.rmtree(server_dir)
    log(f"Server '{clean_target}' removed from database and disk.")


def duplicate_server(from_server: str, to_server: str, custom_dir: str = None):
    clean_from = validate_server_name(from_server)
    clean_to = validate_server_name(to_server)

    conn = get_db()
    row = conn.execute("SELECT * FROM servers WHERE name = ?", (clean_from,)).fetchone()
    if not row:
        log_error(f"Source server '{clean_from}' not found.")
        sys.exit(1)

    src_dir = resolve_server_dir(clean_from)
    dst_dir = Path(custom_dir).resolve() if custom_dir else SERVERS_DIR / clean_to

    if dst_dir.exists():
        log_error(f"Target directory '{dst_dir}' already exists.")
        sys.exit(1)

    log(f"Duplicating server from '{src_dir}' -> '{dst_dir}'...")
    shutil.copytree(src_dir, dst_dir, symlinks=True)

    with conn:
        conn.execute("""
            INSERT INTO servers (id, name, owner_id, minecraftversion, loader, backend, min_ram, max_ram, java_path, server_dir, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            clean_to, clean_to, row["owner_id"], row["minecraftversion"], row["loader"], row["backend"],
            row["min_ram"], row["max_ram"], row["java_path"], str(dst_dir),
            datetime.datetime.now(datetime.timezone.utc).isoformat()
        ))

    log(f"Server duplicated successfully to '{dst_dir}'.")


def parse_args():
    parser = argparse.ArgumentParser(description="AnvilServerHosting Engine (mcserverutil.py)")
    parser.add_argument("--create", action="store_true")
    parser.add_argument("--modify", action="store_true")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--duplicate", action="store_true")
    parser.add_argument("--backup", action="store_true")
    parser.add_argument("--restore", type=str, default=None)
    parser.add_argument("--minecraftversion", "-m", type=str)
    parser.add_argument("--loader", "-l", type=str, default=None)
    parser.add_argument("--backend", type=str, default=None)
    parser.add_argument("--owner", type=str, default="system")
    parser.add_argument("--eulaaccepted", "--eula", action="store_true")
    parser.add_argument("--dir", "-d", type=str, default=None)
    parser.add_argument("--java", "-j", type=str, default=None)
    parser.add_argument("--maxRam", type=str, default=None)
    parser.add_argument("--minRam", type=str, default=None)
    parser.add_argument("--from", dest="from_server", type=str)
    parser.add_argument("--to", dest="to_server", type=str)
    parser.add_argument("--displayname", type=str, default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("positional", nargs="*")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.backup:
        target = args.positional[0] if args.positional else args.from_server
        backup_server(target=target, custom_dir=args.dir)

    elif args.restore:
        target = args.positional[0] if args.positional else args.from_server
        restore_server(target=target, backup_file=args.restore, custom_dir=args.dir)

    elif args.modify:
        target = args.positional[0] if args.positional else args.from_server
        modify_server(
            target=target,
            loader=args.loader,
            java_bin=args.java,
            max_ram=args.maxRam,
            min_ram=args.minRam,
            backend=args.backend,
            custom_dir=args.dir
        )

    elif args.duplicate or (args.from_server and args.to_server):
        if not args.from_server or (not args.to_server and not args.dir):
            log_error("--duplicate requires both --from <servername> and --to <servername> (or --dir <path>)")
            sys.exit(1)
        duplicate_server(from_server=args.from_server, to_server=args.to_server, custom_dir=args.dir)

    elif args.remove:
        target = args.positional[0] if args.positional else args.from_server
        if not target and not args.dir:
            log_error("--remove requires a server name or --dir path.")
            sys.exit(1)
        remove_server(target=target, custom_dir=args.dir)

    elif args.create:
        target = args.positional[0] if args.positional else None
        if not target and not args.dir:
            log_error("--create requires a server name or --dir path.")
            sys.exit(1)
        if not args.minecraftversion:
            log_error("--create requires --minecraftversion <version>.")
            sys.exit(1)
        create_server(
            name=target,
            mc_version=args.minecraftversion,
            loader=args.loader or "paper",
            eula_accepted=args.eulaaccepted,
            java_bin=args.java,
            max_ram=args.maxRam or "4096M",
            min_ram=args.minRam or "1024M",
            custom_dir=args.dir,
            backend=args.backend or "podman",
            owner_id=args.owner,
            display_name=args.displayname
        )

    elif (len(args.positional) == 1 and not (args.from_server or args.to_server)) or args.dir:
        target = args.positional[0] if args.positional else None
        start_server(
            target=target,
            java_override=args.java,
            max_ram_override=args.maxRam,
            min_ram_override=args.minRam,
            custom_dir=args.dir,
            backend_override=args.backend
        )


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)