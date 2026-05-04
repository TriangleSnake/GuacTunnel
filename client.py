#!/usr/bin/env python3
"""
GuacTunnel - Operator-side client
Bridges a local SOCKS5 listener to an Apache Guacamole clipboard tunnel.
"""
import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import struct
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple

import aiohttp
import websockets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("guactunnel")

# ─── Tunnel protocol ──────────────────────────────────────────────────────────

MAGIC = "GT"
MAX_PAYLOAD = 800          # bytes before base64 — keeps clipboard text manageable
POLL_INTERVAL = 0.15       # seconds between clipboard flushes
CONNECT_SETTLE = 0.35      # let clipboard state settle after CONNECTED before DATA
CONNECT_RETRY = 1.5        # retransmit CONNECT while waiting for CONNECTED
DATA_REPEATS = 3           # clipboard is lossy; same-seq repeats are deduped
SEQ_WINDOW = 64            # dedup window size


class Ctrl(str, Enum):
    CONNECT   = "CONNECT"
    CONNECTED = "CONNECTED"
    DATA      = "DATA"
    CLOSE     = "CLOSE"
    PING      = "PING"
    PONG      = "PONG"


def encode_frame(seq: int, chan: int, ctrl: Ctrl, payload: bytes = b"") -> str:
    b64 = base64.b64encode(payload).decode() if payload else ""
    return f"{MAGIC}:{seq}:{chan}:{ctrl.value}:{b64}"


def decode_frame(text: str) -> Optional[Tuple[int, int, Ctrl, bytes]]:
    if not text.startswith(f"{MAGIC}:"):
        return None
    parts = text.split(":", 4)
    if len(parts) != 5:
        return None
    try:
        seq  = int(parts[1])
        chan = int(parts[2])
        ctrl = Ctrl(parts[3])
        data = base64.b64decode(parts[4]) if parts[4] else b""
        return seq, chan, ctrl, data
    except Exception:
        return None


# ─── Guacamole protocol helpers ───────────────────────────────────────────────

def guac_element(s: str) -> str:
    return f"{len(s)}.{s}"


def guac_instruction(*args: str) -> str:
    return ",".join(guac_element(a) for a in args) + ";"


def guac_send_clipboard(stream_id: int, text: str) -> list[str]:
    """Return list of Guacamole instructions to send text via clipboard stream."""
    b64_text = base64.b64encode(text.encode()).decode()
    return [
        guac_instruction("clipboard", str(stream_id), "text/plain"),
        guac_instruction("blob", str(stream_id), b64_text),
        guac_instruction("end", str(stream_id)),
    ]


_GUAC_TOKEN_RE = re.compile(r"(\d+)\.(.*?)(?=,\d+\.|;)", re.DOTALL)

def parse_guac_instruction(raw: str) -> Optional[Tuple[str, list[str]]]:
    """Parse a single Guacamole instruction string → (opcode, [args])."""
    raw = raw.strip().rstrip(";")
    tokens = []
    i = 0
    while i < len(raw):
        dot = raw.index(".", i)
        length = int(raw[i:dot])
        value = raw[dot + 1: dot + 1 + length]
        tokens.append(value)
        i = dot + 1 + length
        if i < len(raw) and raw[i] == ",":
            i += 1
    if not tokens:
        return None
    return tokens[0], tokens[1:]


def split_guac_messages(buf: str) -> Tuple[list[str], str]:
    """Split buffer on ';' boundaries, return (complete_instructions, remainder)."""
    parts = buf.split(";")
    complete = [p + ";" for p in parts[:-1] if p.strip()]
    return complete, parts[-1]


# ─── Guacamole auth & connection ──────────────────────────────────────────────

def guac_base_candidates(raw_url: str) -> list[str]:
    """Return likely Guacamole webapp base URLs, preserving caller preference."""
    first = raw_url.rstrip("/")
    candidates = [first]
    parsed = urllib.parse.urlparse(first)
    path = parsed.path.rstrip("/")

    if path.endswith("/guacamole"):
        parent_path = path[: -len("/guacamole")] or ""
        parent = urllib.parse.urlunparse(parsed._replace(path=parent_path))
        candidates.append(parent.rstrip("/"))
    elif path in ("", "/"):
        guac = urllib.parse.urlunparse(parsed._replace(path="/guacamole"))
        candidates.append(guac.rstrip("/"))

    deduped = []
    for candidate in candidates:
        if candidate and candidate not in deduped:
            deduped.append(candidate)
    return deduped


async def guac_authenticate(session: aiohttp.ClientSession, base_url: str,
                             username: str, password: str) -> tuple[str, str]:
    url = f"{base_url}/api/tokens"
    async with session.post(url, data={"username": username, "password": password},
                            ssl=False) as resp:
        resp.raise_for_status()
        body = await resp.json(content_type=None)
        token = body.get("authToken")
        if not token:
            raise RuntimeError(f"No authToken in response: {body}")
        data_source = body.get("dataSource", "postgresql")
        log.info("Authenticated token=%s… dataSource=%s", token[:12], data_source)
        return token, data_source


async def guac_list_connections(session: aiohttp.ClientSession, base_url: str,
                                token: str, data_source: str = "postgresql") -> Dict:
    url = f"{base_url}/api/session/data/{data_source}/connections"
    async with session.get(url, params={"token": token}, ssl=False) as resp:
        if resp.status == 404:
            url = f"{base_url}/api/session/data/default/connections"
            async with session.get(url, params={"token": token}, ssl=False) as r2:
                r2.raise_for_status()
                return await r2.json(content_type=None)
        resp.raise_for_status()
        return await resp.json(content_type=None)


# ─── Core tunnel state ────────────────────────────────────────────────────────

@dataclass
class Channel:
    chan_id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    target_host: str
    target_port: int
    send_seq: int = 0
    recv_buf: bytearray = field(default_factory=bytearray)
    connected: asyncio.Event = field(default_factory=asyncio.Event)
    connect_failed: bool = False
    closed: bool = False


class GuacTunnel:
    def __init__(self, ws_url: str, token: str, conn_id: str, data_source: str = "postgresql",
                 clear_clipboard: bool = False):
        self.ws_url      = ws_url
        self.token       = token
        self.conn_id     = conn_id
        self.data_source = data_source
        self.clear_clipboard = clear_clipboard

        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._channels: Dict[int, Channel] = {}
        self._next_chan = secrets.randbelow(900_000_000) + 1
        self._send_seq  = secrets.randbelow(1_000_000_000)
        self._recv_seen: deque = deque(maxlen=SEQ_WINDOW)

        # Queue of frames to be written into clipboard
        self._outbox: asyncio.Queue = asyncio.Queue()
        self._stream_id = 1
        self._sent_frames: deque[str] = deque(maxlen=SEQ_WINDOW)

    # ── connection ──

    async def connect(self):
        # Guacamole 1.1+: ALL connection params go in the URL query string.
        # GUAC_DATA_SOURCE is required (the auth dataSource from /api/tokens).
        params = urllib.parse.urlencode({
            "token":            self.token,
            "GUAC_DATA_SOURCE": self.data_source,
            "GUAC_ID":          self.conn_id,
            "GUAC_TYPE":        "c",
            "GUAC_WIDTH":       "1024",
            "GUAC_HEIGHT":      "768",
            "GUAC_DPI":         "96",
            "GUAC_TIMEZONE":    "UTC",
            "GUAC_AUDIO":       "audio/L16;rate=44100,channels=2",
            "GUAC_IMAGE":       "image/png",
        })
        url = f"{self.ws_url}?{params}"
        log.info("Connecting to Guacamole WS: %s", url[:120])
        self._ws = await websockets.connect(
            url,
            subprotocols=["guacamole"],
            ping_interval=None,   # Guacamole manages its own ping via INTERNAL_DATA_OPCODE
            ssl=None,
        )
        log.info("WebSocket connected")
        if self.clear_clipboard:
            await self._clear_remote_clipboard()

    async def run(self):
        await asyncio.gather(
            self._recv_loop(),
            self._send_loop(),
        )

    # ── public API ──

    async def open_channel(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter,
                           target_host: str, target_port: int) -> int:
        cid = self._next_chan
        self._next_chan += 1
        ch = Channel(cid, reader, writer, target_host, target_port)
        self._channels[cid] = ch

        await self._send_connect(ch)
        asyncio.ensure_future(self._channel_reader(ch))
        return cid

    async def _send_connect(self, ch: Channel):
        addr = f"{ch.target_host}:{ch.target_port}"
        await self._enqueue(ch.chan_id, Ctrl.CONNECT, addr.encode())

    async def wait_channel_connected(self, cid: int, timeout: float = 15.0) -> bool:
        ch = self._channels.get(cid)
        if not ch:
            return False

        deadline = asyncio.get_running_loop().time() + timeout
        while not ch.connected.is_set() and not ch.closed:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                log.warning("Channel %d: CONNECT timeout", cid)
                await self.close_channel(cid)
                return False
            try:
                await asyncio.wait_for(ch.connected.wait(), min(CONNECT_RETRY, remaining))
            except asyncio.TimeoutError:
                log.debug("Channel %d: CONNECT retry", cid)
                await self._send_connect(ch)
        return not ch.connect_failed and not ch.closed

    async def close_channel(self, cid: int):
        ch = self._channels.get(cid)
        if ch and not ch.closed:
            ch.closed = True
            ch.connect_failed = True
            ch.connected.set()
            await self._enqueue(cid, Ctrl.CLOSE)
            try:
                ch.writer.close()
                await ch.writer.wait_closed()
            except Exception:
                pass
            self._channels.pop(cid, None)

    async def shutdown(self):
        """Best-effort shutdown: tell the agent to close all open channels."""
        for cid, ch in list(self._channels.items()):
            if not ch.closed:
                ch.closed = True
                ch.connect_failed = True
                ch.connected.set()
                self._send_seq += 1
                frame = encode_frame(self._send_seq, cid, Ctrl.CLOSE)
                with contextlib.suppress(Exception):
                    await self._send_clipboard_frame(frame)
                with contextlib.suppress(Exception):
                    ch.writer.close()
                    await ch.writer.wait_closed()
                self._channels.pop(cid, None)
        if self._ws:
            with contextlib.suppress(Exception):
                await self._ws.close()

    # ── internal ──

    async def _enqueue(self, chan: int, ctrl: Ctrl, payload: bytes = b"", repeats: int = 1):
        self._send_seq += 1
        frame = encode_frame(self._send_seq, chan, ctrl, payload)
        for _ in range(max(1, repeats)):
            await self._outbox.put(frame)

    async def _send_loop(self):
        """Drain outbox → clipboard instructions."""
        while True:
            frame = await self._outbox.get()
            try:
                await self._send_clipboard_frame(frame)
            except Exception as e:
                log.warning("Send error: %s", e)
                break
            await asyncio.sleep(POLL_INTERVAL)

    async def _send_clipboard_frame(self, frame: str):
        self._sent_frames.append(frame)
        log.debug("TX frame %s", frame[:160])
        instructions = guac_send_clipboard(self._stream_id, frame)
        for instr in instructions:
            await self._ws.send(instr)
        self._stream_id = (self._stream_id % 9999) + 1

    async def _clear_remote_clipboard(self):
        frame = ""
        log.debug("Clearing remote clipboard")
        instructions = guac_send_clipboard(self._stream_id, frame)
        for instr in instructions:
            await self._ws.send(instr)
        self._stream_id = (self._stream_id % 9999) + 1
        await asyncio.sleep(POLL_INTERVAL)

    async def _send_sync(self, timestamp: str):
        """Respond to server sync immediately (outside the outbox queue)."""
        try:
            await self._ws.send(guac_instruction("sync", timestamp))
        except Exception:
            pass

    async def _recv_loop(self):
        """Parse incoming Guacamole messages, extract clipboard blobs."""
        buf = ""
        clipboard_streams: Dict[str, str] = {}  # stream_id → accumulated base64

        async for raw in self._ws:
            if isinstance(raw, bytes):
                raw = raw.decode(errors="replace")
            buf += raw
            instructions, buf = split_guac_messages(buf)

            for instr_str in instructions:
                parsed = parse_guac_instruction(instr_str)
                if not parsed:
                    continue
                opcode, args = parsed

                # Must acknowledge every sync to prevent CLIENT_OVERRUN
                if opcode == "sync" and args:
                    await self._send_sync(args[0])

                elif opcode == "clipboard" and len(args) >= 1:
                    sid = args[0]
                    clipboard_streams[sid] = ""

                elif opcode == "blob" and len(args) >= 2:
                    sid, b64 = args[0], args[1]
                    if sid in clipboard_streams:
                        clipboard_streams[sid] += b64

                elif opcode == "end" and len(args) >= 1:
                    sid = args[0]
                    if sid in clipboard_streams:
                        try:
                            text = base64.b64decode(clipboard_streams.pop(sid)).decode(errors="replace")
                            await self._handle_frame(text)
                        except Exception as e:
                            log.debug("Clipboard decode error: %s", e)

                elif opcode == "error":
                    msg = args[0] if args else "unknown"
                    code = args[1] if len(args) > 1 else "?"
                    log.warning("Guacamole error: %s (code %s)", msg, code)

                elif opcode == "disconnect":
                    log.info("Guacamole sent disconnect")

    async def _handle_frame(self, text: str):
        # Some Guacamole/RDP combinations echo client-originated clipboard writes.
        # Ignore exact echoes without suppressing same-sequence responses from the agent.
        if text in self._sent_frames:
            return

        result = decode_frame(text)
        if not result:
            return
        seq, chan, ctrl, payload = result

        if seq in self._recv_seen:
            return
        self._recv_seen.append(seq)
        log.debug("RX frame seq=%d chan=%d ctrl=%s len=%d", seq, chan, ctrl.value, len(payload))

        if ctrl == Ctrl.CONNECTED:
            log.info("Channel %d: remote CONNECTED", chan)
            ch = self._channels.get(chan)
            if ch and not ch.closed:
                ch.connected.set()
                if ch.recv_buf:
                    try:
                        ch.writer.write(bytes(ch.recv_buf))
                        ch.recv_buf.clear()
                        await ch.writer.drain()
                    except Exception:
                        await self.close_channel(chan)

        elif ctrl == Ctrl.DATA:
            ch = self._channels.get(chan)
            if ch and not ch.closed:
                try:
                    if ch.connected.is_set():
                        ch.writer.write(payload)
                        await ch.writer.drain()
                    else:
                        ch.recv_buf.extend(payload)
                except Exception:
                    await self.close_channel(chan)

        elif ctrl == Ctrl.CLOSE:
            ch = self._channels.get(chan)
            if ch:
                ch.connect_failed = not ch.connected.is_set()
                ch.connected.set()
            await self.close_channel(chan)

        elif ctrl == Ctrl.PONG:
            pass

    async def _channel_reader(self, ch: Channel):
        """Read from local TCP connection → outbox."""
        try:
            await ch.connected.wait()
            await asyncio.sleep(CONNECT_SETTLE)
            while not ch.closed:
                data = await ch.reader.read(MAX_PAYLOAD)
                if not data:
                    break
                await self._enqueue(ch.chan_id, Ctrl.DATA, data, repeats=DATA_REPEATS)
        except Exception as e:
            log.debug("Channel %d reader: %s", ch.chan_id, e)
        finally:
            await self.close_channel(ch.chan_id)


# ─── SOCKS5 listener ──────────────────────────────────────────────────────────

SOCKS5_VER     = 0x05
AUTH_NONE      = 0x00
CMD_CONNECT    = 0x01
ATYP_IPV4      = 0x01
ATYP_DOMAIN    = 0x03
ATYP_IPV6      = 0x04


async def handle_socks5(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter,
                        tunnel: GuacTunnel):
    peer = writer.get_extra_info("peername")
    log.debug("SOCKS5 connection from %s", peer)
    try:
        # Greeting
        hdr = await reader.readexactly(2)
        if hdr[0] != SOCKS5_VER:
            writer.close()
            return
        nmethods = hdr[1]
        methods = await reader.readexactly(nmethods)
        # Accept no-auth only
        writer.write(bytes([SOCKS5_VER, AUTH_NONE]))
        await writer.drain()

        # Request
        req = await reader.readexactly(4)
        if req[0] != SOCKS5_VER or req[2] != 0x00:
            writer.close()
            return
        cmd  = req[1]
        atyp = req[3]

        if atyp == ATYP_IPV4:
            addr_bytes = await reader.readexactly(4)
            host = ".".join(str(b) for b in addr_bytes)
        elif atyp == ATYP_DOMAIN:
            alen = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(alen)).decode()
        elif atyp == ATYP_IPV6:
            addr_bytes = await reader.readexactly(16)
            import ipaddress
            host = str(ipaddress.IPv6Address(addr_bytes))
        else:
            writer.close()
            return

        port_bytes = await reader.readexactly(2)
        port = struct.unpack("!H", port_bytes)[0]

        if cmd != CMD_CONNECT:
            # Only CONNECT supported
            writer.write(bytes([SOCKS5_VER, 0x07, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            writer.close()
            return

        log.info("SOCKS5 CONNECT → %s:%d", host, port)

        # Open tunnel channel
        cid = await tunnel.open_channel(reader, writer, host, port)
        if not await tunnel.wait_channel_connected(cid):
            writer.write(bytes([SOCKS5_VER, 0x05, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            writer.close()
            return

        # Reply success
        writer.write(bytes([SOCKS5_VER, 0x00, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError) as e:
        log.debug("SOCKS5 handshake error: %s", e)
        writer.close()


# ─── CLI entry point ──────────────────────────────────────────────────────────

async def main():
    import argparse

    parser = argparse.ArgumentParser(description="GuacTunnel operator client")
    parser.add_argument("--url",      required=True,  help="Guacamole base URL, e.g. http://10.0.10.2:8080/guacamole")
    parser.add_argument("--user",     required=True,  help="Guacamole username")
    parser.add_argument("--password", required=True,  help="Guacamole password")
    parser.add_argument("--conn-id",  help="Guacamole connection ID (numeric)")
    parser.add_argument("--list-conns", action="store_true",
                        help="Authenticate, list available Guacamole connections, and exit")
    parser.add_argument("--socks",    default="127.0.0.1:1080", help="Local SOCKS5 bind address (default: 127.0.0.1:1080)")
    parser.add_argument("--clear-clipboard", action="store_true",
                        help="Clear the Guacamole/RDP clipboard after WebSocket connect")
    parser.add_argument("--debug",    action="store_true")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        logging.getLogger("websockets").setLevel(logging.WARNING)

    socks_host, socks_port = args.socks.rsplit(":", 1)
    socks_port = int(socks_port)

    requested_base_url = args.url.rstrip("/")

    if not args.list_conns and not args.conn_id:
        parser.error("--conn-id is required unless --list-conns is used")

    data_source = "postgresql"
    async with aiohttp.ClientSession() as session:
        base_url = None
        token = None
        last_error = None
        for candidate in guac_base_candidates(requested_base_url):
            try:
                token, data_source = await guac_authenticate(session, candidate, args.user, args.password)
                base_url = candidate
                break
            except Exception as e:
                last_error = e
                log.debug("Auth failed for %s: %s", candidate, e)
        if not base_url or not token:
            raise RuntimeError(f"Could not authenticate to Guacamole at {requested_base_url}: {last_error}")

        ws_base = base_url.replace("http://", "ws://").replace("https://", "wss://")
        ws_url = f"{ws_base}/websocket-tunnel"

        # List connections so user can confirm the ID
        try:
            conns = await guac_list_connections(session, base_url, token, data_source)
            log.info("Available connections:")
            for cid, c in conns.items():
                log.info("  [%s] %s (%s)", cid, c.get("name"), c.get("protocol"))
            if args.list_conns:
                return
        except Exception as e:
            log.warning("Could not list connections: %s", e)
            if args.list_conns:
                raise

    tunnel = GuacTunnel(ws_url, token, args.conn_id, data_source, clear_clipboard=args.clear_clipboard)
    await tunnel.connect()

    server = await asyncio.start_server(
        lambda r, w: handle_socks5(r, w, tunnel),
        socks_host, socks_port,
    )
    log.info("SOCKS5 proxy listening on %s:%d", socks_host, socks_port)
    log.info("Use: curl --socks5 %s:%d http://internal-host/", socks_host, socks_port)

    async with server:
        try:
            await asyncio.gather(
                server.serve_forever(),
                tunnel.run(),
            )
        finally:
            server.close()
            await server.wait_closed()
            await tunnel.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
