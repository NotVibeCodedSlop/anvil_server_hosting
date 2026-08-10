#!/usr/bin/env python3
"""
AnvilServerHosting - Universal Multi-Version Hub Multiplexer (backend/hub_proxy.py)
Compatible with Minecraft 1.7.x through 1.21.x+ (Java & Bedrock via Geyser).
Routes traffic instantly at the TCP Handshake Layer (Zero Packet Desync).
"""

import sys
import os
import re
import json
import sqlite3
import asyncio
import struct
from pathlib import Path

BASE_DIR = Path.home() / ".local" / "share" / "AnvilServerHosting"
DB_PATH = BASE_DIR / "anvil.db"
HUB_PORT = 25565

# Regex to match 16-character hexadecimal server IDs
SERVER_ID_REGEX = re.compile(r'[a-fA-F0-9]{16}')


def read_varint(stream_bytes, offset=0):
    value = 0
    length = 0
    while True:
        if offset + length >= len(stream_bytes):
            return None, offset
        byte = stream_bytes[offset + length]
        value |= (byte & 0x7F) << (length * 7)
        length += 1
        if not (byte & 0x80):
            break
    return value, offset + length


def write_varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def write_string(text):
    data = text.encode('utf-8')
    return write_varint(len(data)) + data


def get_server_port_by_id(server_id: str) -> tuple[int, str]:
    """Queries SQLite for the instance's active dynamic port."""
    if not DB_PATH.exists(): return None, None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT allocated_port, display_name, name 
            FROM servers 
            WHERE id = ? OR name = ?
        """, (server_id, server_id)).fetchone()
        conn.close()

        if not row:
            return None, None

        display_name = row["display_name"] or row["name"]
        active_port = row["allocated_port"]

        # Only return port if server is actively running (> 0)
        if active_port and active_port > 0:
            return active_port, display_name

        return None, display_name
    except Exception:
        return None, None

async def pipe_streams(reader, writer):
    """Pipes raw bidirectional TCP stream with zero packet re-encoding."""
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data: break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try: writer.close(); await writer.wait_closed()
        except Exception: pass


async def handle_client(client_reader, client_writer):
    try:
        # Read the raw initial handshake packet
        header = await client_reader.read(1024)
        if not header:
            client_writer.close()
            return

        pkt_len, offset = read_varint(header, 0)
        if pkt_len is None:
            client_writer.close()
            return

        pkt_id, offset = read_varint(header, offset)

        target_server_id = None
        next_state = 1
        host_str = ""
        proto_ver = 765

        # Packet ID 0x00 = Handshake (Universal across ALL Minecraft versions)
        if pkt_id == 0x00:
            proto_ver, offset = read_varint(header, offset)
            str_len, offset = read_varint(header, offset)
            if str_len and offset + str_len <= len(header):
                host_str = header[offset:offset+str_len].decode('utf-8', errors='ignore')
                offset += str_len
                if offset + 2 <= len(header):
                    port = struct.unpack('>H', header[offset:offset+2])[0]
                    offset += 2
                    next_state, _ = read_varint(header, offset)

            # Search for 16-character hex Server ID anywhere in the host string
            # Handles: "c1417334c0d47df6.domain.com", "domain.com/c1417334c0d47df6", "c1417334c0d47df6"
            matches = SERVER_ID_REGEX.findall(host_str)
            if matches:
                target_server_id = matches[0].lower()

        # ----------------------------------------------------------------------
        # 1. TARGET SERVER FOUND -> INSTANT ZERO-LAG RAW TCP FORWARDING
        # ----------------------------------------------------------------------
        `if target_server_id:
            target_port, srv_name = get_server_port_by_id(target_server_id)
            if target_port:
                try:
                    s_reader, s_writer = await asyncio.open_connection('127.0.0.1', target_port)
                    s_writer.write(header)
                    await s_writer.drain()
                    await asyncio.gather(
                        pipe_streams(client_reader, s_writer),
                        pipe_streams(s_reader, client_writer),
                        return_exceptions=True
                    )
                    return
                except Exception:
                    pass
            elif srv_name:
                # Target server exists but is offline!
                if next_state == 2:  # Login State
                    await client_reader.read(512)
                    kick_msg = {
                        "text": f"§b⚡ Anvil Hub\n\n§cServer '§f{srv_name}§c' is currently OFFLINE!\n\n§ePlease start this server on your web dashboard before connecting."
                    }
                    payload = write_string(json.dumps(kick_msg))
                    client_writer.write(write_varint(len(payload) + 1) + b'\x00' + payload)
                    await client_writer.drain()
                    client_writer.close()
                    return

        # ----------------------------------------------------------------------
        # 2. STATUS PING (SERVER LIST QUERY)
        # ----------------------------------------------------------------------
        if next_state == 1:
            motd_text = (
                "§b⚡ §lAnvil Server Hosting Hub§r\n"
                "§eEnter server as: §f<address>/§a[16-char-code]"
            )
            status_json = json.dumps({
                "version": {"name": "Anvil Hub", "protocol": proto_ver},
                "players": {"max": 100, "online": 0},
                "description": {"text": motd_text}
            })
            payload = write_string(status_json)
            client_writer.write(write_varint(len(payload) + 1) + b'\x00' + payload)
            await client_writer.drain()
            client_writer.close()
            return

        # ----------------------------------------------------------------------
        # 3. UNIVERSAL LOGIN DISCONNECT (COMPATIBLE WITH 1.7.x - 1.21.x+)
        # ----------------------------------------------------------------------
        # Read Login Start packet to clean buffer
        await client_reader.read(512)

        disconnect_json = json.dumps({
            "text": (
                "§b⚡ §lAnvil Server Hosting§r\n\n"
                "§cNo Server Code Specified!\n\n"
                "§eIn your Minecraft Multiplayer Server Address, type:\n"
                "§f<your-server-ip>§a/<your-16-char-code>\n\n"
            )
        })

        # Packet 0x00 in Login State = Login Disconnect (Universal format)
        payload = write_string(disconnect_json)
        client_writer.write(write_varint(len(payload) + 1) + b'\x00' + payload)
        await client_writer.drain()
        client_writer.close()

    except Exception:
        try: client_writer.close(); await client_writer.wait_closed()
        except Exception: pass


async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', HUB_PORT)
    print(f"[AnvilHub] Universal Multi-Version Multiplexer listening on 0.0.0.0:{HUB_PORT}...", flush=True)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\n[AnvilHub] Stopped.")