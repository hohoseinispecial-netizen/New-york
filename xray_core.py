# xray_core.py
# ══════════════════════════════════════════════════════════════════════════════
# مدیریت هسته‌ی Xray کنار برنامه‌ی پایتونی — برای پروتکل‌هایی که توی FastAPI قابل
# پیاده‌سازی نیستن: Reality، gRPC، HTTPUpgrade (و XHTTP روی Reality).
#
# چطور کار می‌کنه:
#   • هر ۵ ثانیه لیست کانفیگ‌های «مجاز» (فعال، منقضی‌نشده، زیر سهمیه) از LINKS خونده می‌شه
#   • از روش یه config.json برای Xray ساخته می‌شه؛ اگه با نسخه‌ی قبلی فرق کرد، اول
#     تست می‌شه (xray run -test) و بعد پراسس ری‌استارت می‌شه
#   • مصرف هر کاربر از stats API خودِ Xray خونده و روی used_bytes جمع می‌شه
#   • کانفیگی که سهمیه‌ش تموم/منقضی/غیرفعال بشه، از config بعدی حذف می‌شه
# محدودیت: speed_limit و ip_limit فقط روی پروتکل‌های پایتونی اعمال می‌شن، نه Xray.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import hashlib
import json
import os
import shutil
import ssl
import time
from collections import deque
from datetime import datetime

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    now_ir,
    is_link_allowed,
    logger,
    log_activity,
    DATA_DIR,
    save_state,
)
from extra_protocols import trojan_password, reality_short_id

# ── تنظیمات (از متغیرهای محیطی) ───────────────────────────────────────────────
XRAY_BIN = os.environ.get("XRAY_BIN", "").strip() or shutil.which("xray") or (
    "/usr/local/bin/xray" if os.path.exists("/usr/local/bin/xray") else ""
)
API_PORT = int(os.environ.get("XRAY_API_PORT", "10085"))
BASE_PORT = int(os.environ.get("XRAY_BASE_PORT", "24430"))
POLL_INTERVAL = 5

GRPC_SERVICE = "nyc-svc"
XHTTP_PATH = "/nyc/u"
HU_PATH = "/nyc/h"

# هر پروتکل = یک inbound مجزا روی پورت مخصوص خودش
SPECS = {
    "vless-reality":       dict(core="vless",  net="tcp",         sec="reality", flow="xtls-rprx-vision"),
    "vless-grpc-reality":  dict(core="vless",  net="grpc",        sec="reality"),
    "vless-xhttp-reality": dict(core="vless",  net="xhttp",       sec="reality"),
    "trojan-reality":      dict(core="trojan", net="tcp",         sec="reality"),
    "vless-httpupgrade":   dict(core="vless",  net="httpupgrade", sec="env"),
}


def _env_map(name: str) -> dict:
    """مثلاً XRAY_PORTS="vless-reality=443,vless-grpc-reality=2053" """
    out = {}
    for part in os.environ.get(name, "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip() in SPECS and v.strip().isdigit():
                out[k.strip()] = int(v.strip())
    return out


_INTERNAL_PORTS = _env_map("XRAY_PORTS")
_PUBLIC_PORTS = _env_map("XRAY_PUBLIC_PORTS")


def internal_port(proto: str) -> int:
    return _INTERNAL_PORTS.get(proto, BASE_PORT + list(SPECS).index(proto))


def public_port(proto: str) -> int:
    """پورتی که توی لینک اشتراک می‌ره (روی ریلوی = پورت TCP-Proxy؛ روی VPS = همون پورت واقعی)."""
    return _PUBLIC_PORTS.get(proto) or internal_port(proto)


def enabled(proto: str) -> bool:
    """XRAY_ENABLED="vless-reality" → فقط همین پروتکل‌ها در «هوشمند» پیشنهاد می‌شن (برای وقتی که فقط یک TCP-Proxy داری)."""
    raw = os.environ.get("XRAY_ENABLED", "").replace(" ", "")
    return not raw or proto in raw.split(",")


def public_host() -> str:
    return os.environ.get("XRAY_PUBLIC_HOST", "").strip()


def httpupgrade_security() -> str:
    """none = پشت CDN/Edge که TLS رو خودش می‌گیره.  tls = گواهی خودت (XRAY_TLS_CERT / XRAY_TLS_KEY)."""
    s = os.environ.get("XRAY_HTTPUPGRADE_SECURITY", "none").strip().lower()
    if s == "tls" and os.environ.get("XRAY_TLS_CERT") and os.environ.get("XRAY_TLS_KEY"):
        return "tls"
    return "none"


# ── وضعیت Reality (کلید + مقصد/SNI) ───────────────────────────────────────────
_STATE_FILE = DATA_DIR / "HVPN_reality.json"
_state = {"private": "", "public": "", "dest": "www.microsoft.com:443", "sni": "www.microsoft.com"}


def _load_state():
    try:
        if _STATE_FILE.exists():
            _state.update(json.loads(_STATE_FILE.read_text(encoding="utf-8")))
    except Exception as e:
        logger.warning(f"Reality state load failed: {e}")
    for env, key in (("XRAY_REALITY_PRIVATE", "private"), ("XRAY_REALITY_PUBLIC", "public"),
                     ("XRAY_REALITY_DEST", "dest"), ("XRAY_REALITY_SNI", "sni")):
        v = os.environ.get(env, "").strip()
        if v:
            _state[key] = v


def _save_state():
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(_state, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Reality state save failed: {e}")


_load_state()


def reality_public() -> str:
    return _state["public"]


def reality_sni() -> str:
    return _state["sni"]


def reality_ready() -> bool:
    return bool(_state["private"] and _state["public"])


# ── اجرای دستورات xray ────────────────────────────────────────────────────────
async def _run(args: list, timeout: float = 10.0):
    try:
        p = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        out, _ = await asyncio.wait_for(p.communicate(), timeout=timeout)
        return p.returncode, out.decode("utf-8", errors="ignore")
    except Exception as e:
        return -1, str(e)


async def ensure_keys() -> bool:
    if reality_ready():
        return True
    if not XRAY_BIN:
        return False
    rc, out = await _run([XRAY_BIN, "x25519"])
    priv = pub = ""
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        k, val = key.lower(), val.strip()
        if "private" in k:
            priv = val
        elif "public" in k or "password" in k:   # نسخه‌های جدید Xray کلید عمومی رو Password می‌نامن
            pub = val
    if rc == 0 and priv and pub:
        _state["private"], _state["public"] = priv, pub
        _save_state()
        logger.info("🔑 Reality keypair generated")
        return True
    logger.warning(f"xray x25519 failed: {out[:200]}")
    return False


# ── ساخت config ──────────────────────────────────────────────────────────────
_PRIVATE_CIDRS = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                  "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"]


def _stream_settings(proto: str, sids: list) -> dict:
    spec = SPECS[proto]
    sec = httpupgrade_security() if spec["sec"] == "env" else spec["sec"]
    ss = {"network": spec["net"], "security": sec}
    if sec == "reality":
        ss["realitySettings"] = {
            "show": False,
            "dest": _state["dest"],
            "xver": 0,
            "serverNames": [_state["sni"]],
            "privateKey": _state["private"],
            "shortIds": sids,
        }
    elif sec == "tls":
        ss["tlsSettings"] = {
            "alpn": ["http/1.1"],
            "certificates": [{"certificateFile": os.environ["XRAY_TLS_CERT"],
                              "keyFile": os.environ["XRAY_TLS_KEY"]}],
        }
    net = spec["net"]
    if net == "grpc":
        ss["grpcSettings"] = {"serviceName": GRPC_SERVICE}
    elif net == "xhttp":
        ss["xhttpSettings"] = {"path": XHTTP_PATH, "mode": "auto"}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": HU_PATH}
    return ss


def build_config(allowed: dict) -> dict:
    inbounds = [{
        "tag": "api", "listen": "127.0.0.1", "port": API_PORT,
        "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"},
    }]
    by_proto: dict = {}
    for uid, l in allowed.items():
        by_proto.setdefault(l["protocol"], []).append(uid)

    for proto, uids in sorted(by_proto.items()):
        spec = SPECS[proto]
        if spec["core"] == "vless":
            clients = []
            for uid in uids:
                c = {"id": uid, "email": uid}
                if spec.get("flow"):
                    c["flow"] = spec["flow"]
                clients.append(c)
            settings = {"clients": clients, "decryption": "none"}
        else:
            settings = {"clients": [{"password": trojan_password(uid), "email": uid} for uid in uids]}
        sids = sorted({reality_short_id(uid) for uid in uids})
        inbounds.append({
            "tag": f"in-{proto}",
            "listen": "0.0.0.0",
            "port": internal_port(proto),
            "protocol": spec["core"],
            "settings": settings,
            "streamSettings": _stream_settings(proto, sids),
        })

    return {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": inbounds,
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                # جلوگیری از دسترسی کاربران به سرویس‌های داخلی سرور (پنل، دیتابیس، ...)
                {"type": "field", "ip": _PRIVATE_CIDRS, "outboundTag": "block"},
            ],
        },
    }


# ── مدیریت پراسس ─────────────────────────────────────────────────────────────
CFG_FILE = DATA_DIR / "xray_config.json"
_proc = None
_last_sig = ""
_retry_after = 0.0
_last_save = 0.0
_dirty = False
_log_tail: deque = deque(maxlen=25)
_version = ""
_status = {"last_error": ""}
_task = None


def _alive() -> bool:
    return _proc is not None and _proc.returncode is None


async def _drain(p):
    try:
        while True:
            line = await p.stdout.readline()
            if not line:
                break
            txt = line.decode("utf-8", errors="ignore").rstrip()
            if txt:
                _log_tail.append(txt)
                logger.info(f"[xray] {txt}")
    except Exception:
        pass


async def _stop():
    global _proc
    p, _proc = _proc, None
    if p and p.returncode is None:
        p.terminate()
        try:
            await asyncio.wait_for(p.wait(), 5)
        except asyncio.TimeoutError:
            p.kill()
            await p.wait()


async def _apply(cfg: dict) -> bool:
    """اول config رو تست می‌کنه؛ فقط اگه سالم بود پراسس قبلی رو با جدید عوض می‌کنه."""
    global _proc
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CFG_FILE.with_suffix(".new")
    tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    rc, out = await _run([XRAY_BIN, "run", "-test", "-c", str(tmp)])
    if rc != 0:
        _status["last_error"] = f"config test failed: {out.strip()[-300:]}"
        logger.warning(_status["last_error"])
        return False
    tmp.replace(CFG_FILE)
    await _stop()
    _proc = await asyncio.create_subprocess_exec(
        XRAY_BIN, "run", "-c", str(CFG_FILE),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    asyncio.create_task(_drain(_proc))
    await asyncio.sleep(0.8)
    if _proc.returncode is not None:
        _status["last_error"] = "xray exited right after start: " + " | ".join(list(_log_tail)[-3:])
        logger.warning(_status["last_error"])
        return False
    _status["last_error"] = ""
    logger.info(f"🚀 Xray restarted ({len(cfg['inbounds']) - 1} inbound)")
    return True


async def _snapshot() -> dict:
    async with LINKS_LOCK:
        return {uid: dict(l) for uid, l in LINKS.items()
                if l.get("protocol") in SPECS and is_link_allowed(l)}


async def _poll_stats():
    """مصرف هر کاربر از stats API (با -reset تا فقط دلتا برگرده) روی used_bytes جمع می‌شه."""
    global _dirty
    if not _alive():
        return
    rc, out = await _run([XRAY_BIN, "api", "statsquery", "-s", f"127.0.0.1:{API_PORT}",
                          "-pattern", "user>>>", "-reset"], timeout=8)
    if rc != 0:
        return
    try:
        data = json.loads(out)
    except Exception:
        return
    totals: dict = {}
    for s in data.get("stat", []) or []:
        parts = str(s.get("name", "")).split(">>>")
        if len(parts) >= 4 and parts[0] == "user":
            try:
                totals[parts[1]] = totals.get(parts[1], 0) + int(s.get("value") or 0)
            except (TypeError, ValueError):
                pass
    grand = sum(totals.values())
    if not grand:
        return
    async with LINKS_LOCK:
        for uid, n in totals.items():
            if uid in LINKS:
                LINKS[uid]["used_bytes"] += n
        stats["total_bytes"] += grand
        hourly_traffic[now_ir().strftime("%H:00")] += grand
    _dirty = True


async def _tick():
    global _last_sig, _retry_after, _last_save, _dirty
    if not XRAY_BIN:
        return
    await ensure_keys()
    allowed = await _snapshot()

    if not allowed:
        if _alive():
            await _poll_stats()
            await _stop()
        _last_sig = ""
        return
    if not reality_ready():
        return

    cfg = build_config(allowed)
    sig = hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()
    need = sig != _last_sig or not _alive()
    if need and time.time() >= _retry_after:
        if _alive():
            await _poll_stats()       # قبل از ری‌استارت شمارنده‌ها رو بگیر که از دست نرن
        if await _apply(cfg):
            _last_sig = sig
        else:
            _retry_after = time.time() + 30
    else:
        await _poll_stats()

    if _dirty and time.time() - _last_save > 30:
        _dirty = False
        _last_save = time.time()
        asyncio.create_task(save_state())


async def _loop():
    while True:
        try:
            await _tick()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"xray loop error: {e}")
        await asyncio.sleep(POLL_INTERVAL)


async def start_xray():
    global _task, _version
    if not XRAY_BIN:
        logger.info("Xray: باینری پیدا نشد؛ پروتکل‌های Reality/gRPC/HTTPUpgrade غیرفعال‌ان (XRAY_BIN رو تنظیم کن).")
        return
    rc, out = await _run([XRAY_BIN, "version"])
    _version = out.splitlines()[0] if rc == 0 and out else ""
    logger.info(f"Xray found: {_version or XRAY_BIN}")
    _task = asyncio.create_task(_loop())


async def stop_xray():
    if _task:
        _task.cancel()
    await _poll_stats()
    await _stop()


# ── اطلاعات برای پنل / هوشمند ─────────────────────────────────────────────────
def status_brief() -> dict:
    return {
        "available": bool(XRAY_BIN),
        "running": _alive(),
        "version": _version,
        "reality_ready": reality_ready(),
        "reality_sni": _state["sni"],
        "reality_dest": _state["dest"],
        "httpupgrade_security": httpupgrade_security(),
        "public_host": public_host(),
        "enabled": [p for p in SPECS if enabled(p)],
        "ports": {p: {"internal": internal_port(p), "public": public_port(p)} for p in SPECS},
        "last_error": _status["last_error"],
        "log_tail": list(_log_tail)[-8:],
    }


# ── انتخاب بهترین مقصد Reality (اندازه‌گیری واقعی از روی خودِ سرور) ─────────────
REALITY_CANDIDATES = [
    "www.microsoft.com", "www.apple.com", "www.samsung.com", "dl.google.com",
    "addons.mozilla.org", "www.nvidia.com", "www.amd.com", "www.cisco.com",
    "www.speedtest.net", "www.lovelive-anime.jp",
]


async def _probe(host: str) -> dict:
    """مقصد خوب Reality: TLS 1.3 + ALPN=h2 داشته باشه و از سرور شما سریع جواب بده."""
    res = {"host": host, "ok": False, "ms": None, "tls": "", "alpn": "", "error": ""}
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    t0 = time.monotonic()
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host), timeout=6)
        so = w.get_extra_info("ssl_object")
        res["ms"] = round((time.monotonic() - t0) * 1000)
        res["tls"] = so.version() if so else ""
        res["alpn"] = (so.selected_alpn_protocol() if so else "") or ""
        res["ok"] = res["tls"] == "TLSv1.3" and res["alpn"] == "h2"
        w.close()
    except Exception as e:
        res["error"] = type(e).__name__
    return res


async def scan_reality(candidates: list | None = None) -> list:
    results = await asyncio.gather(*[_probe(h) for h in (candidates or REALITY_CANDIDATES)])
    results.sort(key=lambda r: (not r["ok"], r["ms"] if r["ms"] is not None else 10 ** 6))
    return results


def set_reality_target(host: str):
    """توجه: با تغییر SNI، لینک‌های Reality قبلی (که SNI قدیمی توشونه) باید دوباره به کاربرها داده بشن."""
    _state["sni"] = host
    _state["dest"] = f"{host}:443"
    _save_state()
    log_activity("system", f"مقصد Reality روی {host} تنظیم شد", "info")
