# smart.py
# ══════════════════════════════════════════════════════════════════════════════
# بخش «هوشمند»: ترکیب‌های پروتکل × ترنسپورت × امنیت (TLS / Reality) رو بر اساس هدف
# کاربر امتیازدهی می‌کنه، فقط ترکیب‌هایی رو که روی همین سرور واقعاً قابل اجرا هستن
# پیشنهاد می‌ده، و با یک کلیک چند کانفیگ متنوع (fingerprint های مختلف) توی یک گروه
# ساب می‌سازه. همچنین بهترین مقصد Reality رو با اندازه‌گیری واقعی از روی سرور انتخاب می‌کنه.
#
# توجه: این یک موتور قاعده‌محور (rule-based) با امتیازهای ثابت هست، نه تست زنده‌ی
# فیلترینگ روی شبکه‌ی کاربر. امتیازها تجربه‌ی عمومی جامعه‌ی Xray هستن و قابل تغییرن (PRESETS).
# ══════════════════════════════════════════════════════════════════════════════

from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Depends, HTTPException

from main import (
    require_auth,
    make_link,
    create_sub_group,
    get_host,
    vless_link_for_link,
    parse_size_to_bytes,
    parse_speed_to_bytes,
    DEFAULT_PORT,
    log_activity,
)
import xray_core as xc

router = APIRouter()

GOALS = {
    "balanced": {"title": "متعادل", "w": dict(stealth=.35, speed=.30, stability=.25, cdn=.10)},
    "stealth":  {"title": "حداکثر مخفی‌کاری", "w": dict(stealth=.60, speed=.15, stability=.20, cdn=.05)},
    "speed":    {"title": "حداکثر سرعت", "w": dict(stealth=.20, speed=.55, stability=.20, cdn=.05)},
    "compat":   {"title": "ثبات و سازگاری با CDN", "w": dict(stealth=.10, speed=.10, stability=.40, cdn=.40)},
}

FP_ROTATION = ["chrome", "firefox", "safari", "edge", "ios", "android"]

# امتیازها از ۰ تا ۱۰
PRESETS = [
    dict(id="vless-reality-vision", protocol="vless-reality", engine="xray", alpn="",
         title="Line R1",
         scores=dict(stealth=10, speed=9, stability=8, cdn=0),
         why="دست‌دادن TLS یک سایت واقعی رو تقلید می‌کنه و به دامنه/گواهی نیاز نداره. Vision رمزگذاری دوباره‌ی TLS رو حذف می‌کنه، پس سریع‌ترین مسیر هم هست."),
    dict(id="vless-grpc-reality", protocol="vless-grpc-reality", engine="xray", alpn="",
         title="Line R2",
         scores=dict(stealth=9, speed=8, stability=8, cdn=0),
         why="ترافیک شبیه HTTP/2 است و چند جریان رو روی یک اتصال می‌بره؛ روی شبکه‌های ناپایدار و موبایل خوب جواب می‌ده."),
    dict(id="vless-xhttp-reality", protocol="vless-xhttp-reality", engine="xray", alpn="",
         title="Line R3",
         scores=dict(stealth=9, speed=9, stability=7, cdn=0),
         why="جدیدترین ترنسپورت Xray روی Reality؛ الگوی ترافیک متنوع‌تر و سخت‌تر برای تشخیص ساده. نیاز به Xray نسبتاً جدید دارد."),
    dict(id="trojan-reality", protocol="trojan-reality", engine="xray", alpn="",
         title="Line R4",
         scores=dict(stealth=8, speed=8, stability=8, cdn=0),
         why="جایگزین مستقل از VLESS؛ وقتی امضای VLESS روی شبکه‌ی کاربر مسدود شده باشه."),
    dict(id="xhttp-stream-up", protocol="xhttp-stream-up", engine="python", alpn="h2,http/1.1",
         title="Line B2",
         scores=dict(stealth=7, speed=8, stability=6, cdn=8),
         why="روی دامنه‌ی HTTPS خودِ سرویس (بدون پورت اضافه) و با تأخیر کم؛ پشت CDN هم کار می‌کنه."),
    dict(id="xhttp-packet-up", protocol="xhttp-packet-up", engine="python", alpn="h2,http/1.1",
         title="Line B1",
         scores=dict(stealth=7, speed=6, stability=8, cdn=9),
         why="سازگارترین حالت XHTTP با CDN و پراکسی‌ها؛ کمی سربار بیشتر."),
    dict(id="vless-ws-tls", protocol="vless-ws", engine="python", alpn="http/1.1",
         title="Line A1",
         scores=dict(stealth=6, speed=6, stability=9, cdn=10),
         why="قدیمی ولی پایدار و تقریباً با همه‌ی کلاینت‌ها و CDNها سازگار؛ انتخاب امن برای پشتیبان."),
    dict(id="trojan-ws-tls", protocol="trojan-ws", engine="python", alpn="http/1.1",
         title="Line C1",
         scores=dict(stealth=6, speed=6, stability=8, cdn=9),
         why="همون مسیر WS ولی با امضای Trojan؛ اگه پروتکل VLESS روی شبکه‌ی کاربر سخت‌گیری بشه یدک خوبیه."),
    dict(id="vless-httpupgrade", protocol="vless-httpupgrade", engine="xray", alpn="http/1.1",
         title="Line H1",
         scores=dict(stealth=5, speed=7, stability=7, cdn=9),
         why="سبک‌تر از WebSocket چون فریم‌بندی نداره. فقط پشت CDN/Edge که TLS رو می‌گیره منطقیه."),
]


def _availability(p: dict):
    """(در دسترس؟، دلیل، هشدار)"""
    if p["engine"] == "python":
        return True, "", ""
    st = xc.status_brief()
    if not st["available"]:
        return False, "هسته‌ی Xray روی سرور نصب نیست (XRAY_BIN)", ""
    if not xc.enabled(p["protocol"]):
        return False, "روی این سرور فعال نشده (XRAY_ENABLED)", ""
    if p["protocol"] == "vless-httpupgrade":
        if st["httpupgrade_security"] == "none":
            return True, "", "TLS روی خود پورت نیست؛ فقط پشت CDN/Edge امنه."
        return True, "", ""
    if not st["reality_ready"]:
        return False, "کلید Reality هنوز ساخته نشده (چند ثانیه صبر کن و دوباره بزن)", ""
    return True, "", ""


def _score(p: dict, goal: str, warn: str) -> int:
    w = GOALS[goal]["w"]
    s = sum(w[k] * p["scores"][k] for k in w) * 10
    if warn:
        s -= 15
    return max(0, round(s))


def plan(goal: str = "balanced", count: int = 4, only: list | None = None) -> dict:
    if goal not in GOALS:
        goal = "balanced"
    count = max(1, min(int(count or 4), 8))
    items = []
    for p in PRESETS:
        if only and p["id"] not in only:
            continue
        ok, reason, warn = _availability(p)
        items.append({
            "id": p["id"], "title": p["title"], "protocol": p["protocol"], "engine": p["engine"],
            "scores": p["scores"], "why": p["why"], "alpn": p["alpn"],
            "available": ok, "reason": reason, "warn": warn,
            "score": _score(p, goal, warn),
        })
    items.sort(key=lambda x: (not x["available"], -x["score"]))
    chosen = [i for i in items if i["available"]][:count]
    for idx, i in enumerate(chosen):
        i["selected"] = True
        i["fingerprint"] = FP_ROTATION[idx % len(FP_ROTATION)]
    return {"goal": goal, "goal_title": GOALS[goal]["title"], "items": items, "count": len(chosen)}


async def build_smart_pack(
    host: str,
    goal: str = "balanced",
    count: int = 4,
    label: str = "هوشمند",
    presets: list | None = None,
    limit_bytes: int = 0,
    expires_at: str | None = None,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    group: bool = True,
    group_name: str | None = None,
) -> dict:
    await xc.ensure_keys()
    pl = plan(goal, count, presets)
    chosen = [i for i in pl["items"] if i.get("selected")]
    if not chosen:
        raise HTTPException(status_code=400, detail="هیچ ترکیب قابل‌اجرایی روی این سرور پیدا نشد")

    sub_id, sub = None, None
    if group:
        sub_id, sub = await create_sub_group(name=group_name or f"هوشمند · {pl['goal_title']}")

    out = []
    for i in chosen:
        uid, link = await make_link(
            label=f"{label} · {i['title']}",
            limit_bytes=limit_bytes,
            expires_at=expires_at,
            note=f"smart:{goal}",
            sub_id=sub_id,
            protocol=i["protocol"],
            fingerprint=i["fingerprint"],
            alpn=i["alpn"],
            port=DEFAULT_PORT,
            ip_limit=ip_limit,
            speed_limit_bytes=speed_limit_bytes,
        )
        out.append({
            "uuid": uid, "label": link["label"], "protocol": i["protocol"], "title": i["title"],
            "fingerprint": i["fingerprint"], "score": i["score"], "warn": i["warn"],
            "vless_link": vless_link_for_link(link, uid, host),
            "sub_url": f"https://{host}/sub/{uid}",
        })
    log_activity("smart", f"بسته‌ی هوشمند «{pl['goal_title']}» با {len(out)} کانفیگ ساخته شد", "ok")
    return {
        "goal": goal,
        "group": ({"sub_id": sub_id, "name": sub["name"], "public_url": f"https://{host}/p/{sub['uuid_key']}"}
                  if sub else None),
        "links": out,
    }


# ── API ───────────────────────────────────────────────────────────────────────
@router.get("/api/smart/status")
async def smart_status(_=Depends(require_auth)):
    await xc.ensure_keys()
    return {"xray": xc.status_brief(),
            "goals": [{"id": k, "title": v["title"]} for k, v in GOALS.items()]}


@router.get("/api/smart/plan")
async def smart_plan(goal: str = "balanced", count: int = 4, _=Depends(require_auth)):
    await xc.ensure_keys()
    return plan(goal, count)


@router.post("/api/smart/scan")
async def smart_scan(request: Request, _=Depends(require_auth)):
    """مقصد/SNI مناسب Reality رو از روی سرور امتحان می‌کنه. با apply=true بهترینش رو اعمال می‌کنه."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    results = await xc.scan_reality()
    applied = None
    if body.get("apply"):
        best = next((r for r in results if r["ok"]), None)
        if best is None:
            raise HTTPException(status_code=400, detail="هیچ مقصد مناسبی (TLS1.3 + h2) پیدا نشد")
        xc.set_reality_target(best["host"])
        applied = best["host"]
    return {"results": results, "applied": applied, "current": xc.reality_sni()}


@router.post("/api/smart/build")
async def smart_build(request: Request, _=Depends(require_auth)):
    body = await request.json()
    lv = float(body.get("limit_value") or 0)
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, body.get("limit_unit") or "GB")
    days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    sv = float(body.get("speed_limit_value") or 0)
    speed = 0 if sv <= 0 else parse_speed_to_bytes(sv, body.get("speed_limit_unit") or "MBIT")
    return await build_smart_pack(
        get_host(request),
        goal=body.get("goal") or "balanced",
        count=int(body.get("count") or 4),
        label=(body.get("label") or "هوشمند").strip()[:30],
        presets=body.get("presets") or None,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        ip_limit=int(body.get("ip_limit") or 0),
        speed_limit_bytes=speed,
        group=bool(body.get("group", True)),
        group_name=(body.get("group_name") or "").strip()[:60] or None,
    )
