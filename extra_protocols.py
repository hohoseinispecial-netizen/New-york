# extra_protocols.py
# ══════════════════════════════════════════════════════════════════════════════
# پروتکل‌های جدید HVPN:
#   • trojan-ws  → کاملاً داخل همین پایتون (پشت TLS خودِ Railway/CDN) — مثل VLESS/WS
#   • Reality / gRPC / HTTPUpgrade → توسط هسته‌ی Xray سرو می‌شن (xray_core.py)؛
#     این فایل فقط «لینک اشتراک» اونا رو می‌سازه.
# رمز Trojan و shortId ریلیتی از روی UUID کانفیگ + SECRET_KEY مشتق می‌شن، پس
# نیازی به فیلد جدید توی HVPN_state.json نیست و کانفیگ‌های قدیمی دست‌نخورده می‌مونن.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import hashlib
import ipaddress
import secrets
import socket
from datetime import datetime
from urllib.parse import quote

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    CONFIG,
    LINKS,
    LINKS_LOCK,
    stats,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
    log_activity,
    FINGERPRINTS,
    DEFAULT_FINGERPRINT,
    DEFAULT_ALPN_BY_PROTOCOL,
    DEFAULT_PORT,
    MIN_PORT,
    MAX_PORT,
)
from relay_vless import check_and_use, relay_ws_to_tcp, _ws_client_ip, RELAY_BUF
from speed_limit import throttle


# ── مشتق‌سازی اسرار هر کانفیگ ─────────────────────────────────────────────────
def _derive(tag: str, uid: str, n: int) -> str:
    return hashlib.sha256(f"{tag}:{uid}:{CONFIG['secret']}".encode()).hexdigest()[:n]


def trojan_password(uid: str) -> str:
    return _derive("trojan", uid, 24)


def trojan_hash(uid: str) -> str:
    """Trojan به‌جای خودِ رمز، sha224 هگز اون رو توی هدر می‌فرسته."""
    return hashlib.sha224(trojan_password(uid).encode()).hexdigest()


def reality_short_id(uid: str) -> str:
    return _derive("sid", uid, 8)


# ── ساخت لینک اشتراک ──────────────────────────────────────────────────────────
def _query(params: dict) -> str:
    return "&".join(f"{k}={quote(str(v))}" for k, v in params.items() if v not in (None, ""))


def build_extra_link(link: dict, uid: str, host: str, remark: str) -> str:
    """لینک اشتراک برای trojan-ws و پروتکل‌های Xray (reality / grpc / httpupgrade / xhttp-reality)."""
    import xray_core as xc

    proto = link.get("protocol")
    fp = (link.get("fingerprint") or DEFAULT_FINGERPRINT).strip() or DEFAULT_FINGERPRINT
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    user_alpn = (link.get("alpn") or "").strip()
    try:
        port = int(link.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    if not (MIN_PORT <= port <= MAX_PORT):
        port = DEFAULT_PORT
    tag = "#" + quote(remark)

    # ── Trojan + WebSocket (پایتون) ──
    if proto == "trojan-ws":
        params = {
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": f"/nyc/b/{uid}",
            "sni": host,
            "fp": fp,
            "alpn": user_alpn or DEFAULT_ALPN_BY_PROTOCOL.get(proto, "http/1.1"),
        }
        return f"trojan://{trojan_password(uid)}@{host}:{port}?{_query(params)}{tag}"

    # ── پروتکل‌های Xray ──
    spec = xc.SPECS.get(proto)
    if spec is None:
        raise ValueError(f"unknown protocol: {proto}")
    xhost = xc.public_host() or host
    # اگه کاربر پورت دستی گذاشته همون؛ وگرنه پورت عمومی همین پروتکل (مثلاً پورت TCP-Proxy ریلوی)
    xport = port if port != DEFAULT_PORT else xc.public_port(proto)

    params: dict = {}
    if spec["core"] == "vless":
        params["encryption"] = "none"
    if spec.get("flow"):
        params["flow"] = spec["flow"]

    sec = spec["sec"]
    if sec == "env":
        sec = xc.httpupgrade_security()
    params["security"] = sec

    net = spec["net"]
    params["type"] = net
    if net == "tcp":
        params["headerType"] = "none"
    elif net == "grpc":
        params["serviceName"] = xc.GRPC_SERVICE
        params["mode"] = "gun"
    elif net == "xhttp":
        params["mode"] = "auto"
        params["path"] = xc.XHTTP_PATH
    elif net == "httpupgrade":
        params["host"] = xhost
        params["path"] = xc.HU_PATH

    if sec == "reality":
        params["sni"] = xc.reality_sni()
        params["fp"] = fp
        params["pbk"] = xc.reality_public()
        params["sid"] = reality_short_id(uid)
        params["spx"] = "/"
    elif sec == "tls":
        params["sni"] = xhost
        params["fp"] = fp
        params["alpn"] = user_alpn or "http/1.1"

    scheme = spec["core"]
    ident = uid if scheme == "vless" else trojan_password(uid)
    return f"{scheme}://{ident}@{xhost}:{xport}?{_query(params)}{tag}"


# ══════════════════════════════════════════════════════════════════════════════
# Trojan over WebSocket — relay
# ══════════════════════════════════════════════════════════════════════════════
def parse_trojan_header(chunk: bytes, expected_hash: str):
    """
    ساختار: hex(sha224(password)) [56 بایت] CRLF  CMD  ATYP  ADDR  PORT  CRLF  payload
    ATYP: 1=IPv4  3=دامنه  4=IPv6   (توجه: با VLESS فرق داره)
    """
    if len(chunk) < 56 + 2 + 1 + 1 + 1 + 2 + 2:
        raise ValueError("trojan header too small")
    got = chunk[:56].decode("ascii", errors="ignore")
    if not secrets.compare_digest(got, expected_hash):
        raise PermissionError("bad trojan password")
    if chunk[56:58] != b"\r\n":
        raise ValueError("bad trojan header (crlf)")
    pos = 58
    cmd = chunk[pos]; pos += 1
    atyp = chunk[pos]; pos += 1
    if atyp == 1:
        address = ".".join(str(b) for b in chunk[pos:pos + 4]); pos += 4
    elif atyp == 3:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos + dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif atyp == 4:
        address = ipaddress.IPv6Address(bytes(chunk[pos:pos + 16])).compressed; pos += 16
    else:
        raise ValueError(f"unknown trojan atyp: {atyp}")
    port = int.from_bytes(chunk[pos:pos + 2], "big"); pos += 2
    if chunk[pos:pos + 2] != b"\r\n":
        raise ValueError("bad trojan header (tail crlf)")
    pos += 2
    return cmd, address, port, chunk[pos:]


async def _tcp_to_ws_plain(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    """برخلاف VLESS، Trojan هدر پاسخ نداره؛ بایت‌ها همون‌طور که هستن برمی‌گردن."""
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            await throttle(uid, len(data))
            c = connections.get(conn_id)
            if c is not None:
                c["bytes"] += len(data)
            await ws.send_bytes(data)
    except Exception:
        pass


async def trojan_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link) or link.get("protocol") != "trojan-ws":
        logger.warning(f"🚫 Trojan-WS rejected uuid={uuid[:8]}… (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    ip = _ws_client_ip(ws)
    if not is_ip_allowed(link, uuid, ip):
        logger.warning(f"🚫 Trojan-WS rejected uuid={uuid[:8]}… ip={ip} (ip limit reached)")
        log_activity("connection", f"اتصال {ip} به کانفیگ «{link.get('label','?')}» رد شد (محدودیت تعداد آی‌پی)", "warn")
        await ws.close(code=1008, reason="ip limit reached")
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "trojan-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ Trojan-WS [{conn_id}] uuid={uuid[:8]}… ip={ip} total={len(connections)}")
    log_activity("connection", f"اتصال جدید (Trojan) از {ip} (کانفیگ {link.get('label','?')})", "info")
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        try:
            cmd, address, port, payload = parse_trojan_header(first_chunk, trojan_hash(uuid))
        except PermissionError:
            log_activity("connection", f"رمز Trojan اشتباه از {ip}", "err")
            await ws.close(code=1008, reason="bad password")
            return
        if cmd != 1:
            # فقط CONNECT (TCP)؛ UDP-associate (cmd=3) پشتیبانی نمی‌شه
            await ws.close(code=1008, reason="unsupported command")
            return

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"➡️  Trojan [{conn_id}] → {address}:{port}")

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        sock = writer.transport.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(_tcp_to_ws_plain(ws, reader, conn_id, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        asyncio.create_task(save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "trojan connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"Trojan-WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 Trojan-WS closed [{conn_id}] total={len(connections)}")
