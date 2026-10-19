#!/usr/bin/env python3
"""
status.cguardpro.com — la página de estado de CGuard Pro, generada FUERA del
servidor de producción.

Dos modos, un solo fichero (así las reglas no se desincronizan):

· MODO CASA (por defecto): corre en el R620 cada minuto (systemd timer). Sondea
  las piezas públicas por el mismo camino que usan los clientes (Cloudflare →
  túnel → .19), guarda la historia de 90 días, deduce los incidentes
  automáticos, lee del API los mantenimientos programados y los incidentes
  escritos a mano (y se queda con la última copia si el API no contesta: justo
  cuando más falta hace), lee la vista «desde fuera» que publica GitHub, y
  escribe status.json + feed.xml + index.html en la carpeta que nginx sirve.

· MODO FUERA (--external): corre en GitHub Actions cada 5 minutos, desde fuera
  de la casa. Sondea las mismas piezas, comprueba que la página de la casa
  está fresca y escribe external.json (con su propia historia de 7 días).
  Avisa por Telegram (sin pasar por la casa, que puede ser lo que está caído).

· --export-page: imprime el index.html de la copia de respaldo (GitHub Pages),
  que carga los datos de la casa y, si no puede, los de fuera.

Sólo biblioteca estándar: ni en el R620 ni en GitHub hay que instalar nada.

Reglas (las que decidimos después del cf-watchdog que dio verde 7 meses sobre
un sitio muerto): una sonda está bien sólo si el código es 2xx/3xx Y el cuerpo
trae el marcador esperado Y no coincide con ninguna página rota conocida.
"""
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from html import escape

CONF = os.environ.get("CGUARD_STATUS_CONF", "/etc/cguard-status/components.json")
STATE_DIR = os.environ.get("CGUARD_STATUS_STATE", "/var/lib/cguard-status")
OUT_DIR = os.environ.get("CGUARD_STATUS_OUT", "/data/docker/portal/html/estado-cguard")
HQ_ENV = "/data/docker/hq/.env"
HQ_HOOK = "http://127.0.0.1/api/hooks/cguard/{token}"
HISTORY_DAYS = 90
EXTERNAL_HISTORY_DAYS = 7
INCIDENT_DAYS = 30
FRESH_MINUTES = 10  # una página de estado con más de 10 min sin actualizar está vieja
BROKEN = re.compile(
    r"has been stopped|Web server is down|Error 10\d\d|Bad gateway|502 Bad|503 Service|Origin is unreachable|cloudflare.*error",
    re.I,
)
UA = "cguard-status-probe/2 (+https://status.cguardpro.com)"
LANGS = ["es", "en", "pt", "fr", "de", "it", "nl", "pl"]


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_atomic(path, text):
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def fetch(url, timeout, method="GET", data=None, headers=None):
    """Devuelve (código, cuerpo[:200k], segundos, error)."""
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h, method=method, data=data)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as r:
            body = r.read(400_000).decode("utf-8", "replace")
            return r.status, body, time.monotonic() - t0, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4000).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body, time.monotonic() - t0, f"http {e.code}"
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError, ValueError) as e:
        return 0, "", time.monotonic() - t0, str(getattr(e, "reason", e))[:160]


def probe(component, conf):
    """Estado de una pieza: ok · degraded · down, con el detalle."""
    timeout = conf.get("timeout_seconds", 12)
    slow = conf.get("slow_seconds", 5)
    accept = set(component.get("accept_codes") or [])
    # `marker` (uno) o `markers` (vale cualquiera): desde fuera de casa el CRM
    # manda a las IP de nube a la verificación humana, y esa página también
    # demuestra que el borde, nginx y el API están vivos.
    markers = [m for m in ([component.get("marker")] + list(component.get("markers") or [])) if m]
    marker = markers[0] if markers else ""

    def one():
        code, body, secs, err = fetch(component["url"], timeout)
        body = body[:4000]
        healthy_code = (200 <= code < 400) or (code in accept)
        if not healthy_code:
            return "down", f"{err or ('http ' + str(code))}", secs
        if BROKEN.search(body) and code not in accept:
            return "down", "página rota del borde", secs
        if markers and not any(m in body for m in markers):
            return "down", "respondió pero sin el contenido esperado", secs
        if secs > slow:
            return "degraded", f"lento ({secs:.1f} s)", secs
        return "ok", f"{code} en {secs:.2f} s", secs

    state, detail, secs = one()
    if state == "down":
        # Un fallo aislado de red no es una caída: se confirma a los 3 s.
        time.sleep(3)
        state, detail, secs = one()

    lan = None
    if component.get("lan") and state != "ok":
        code, body, lsecs, err = fetch(component["lan"], min(timeout, 6))
        lan = "ok" if (200 <= code < 400 and (not marker or marker in body[:4000])) else "down"
    return {"id": component["id"], "state": state, "detail": detail, "seconds": round(secs, 2), "lan": lan}


# ── Avisos del API: mantenimientos programados e incidentes escritos a mano ──

def load_notices(conf, cache_path):
    """Avisos del API. Si no contesta, la última copia buena (marcada stale)."""
    url = conf.get("notices_url")
    if url:
        code, body, _, err = fetch(url, 8)
        if code == 200:
            try:
                data = json.loads(body)
                data = data.get("data", data) if isinstance(data, dict) else data
                if isinstance(data, dict) and isinstance(data.get("maintenance"), list):
                    data.setdefault("incidents", [])
                    data["fetchedAt"] = iso(now_utc())
                    if cache_path:
                        write_atomic(cache_path, json.dumps(data))
                    return data, False
            except Exception:
                pass
    cached = read_json(cache_path, {"maintenance": [], "incidents": []}) if cache_path else {"maintenance": [], "incidents": []}
    cached.setdefault("incidents", [])
    return cached, True


def maintenance_status(m, now):
    start = parse_iso(m.get("startsAt")) if m.get("startsAt") else None
    end = parse_iso(m.get("endsAt")) if m.get("endsAt") else None
    if start and now < start:
        return "scheduled"
    if end and now > end:
        return "completed"
    return "in_progress"


def maintenance_list(notices, now):
    maint = []
    for m in notices.get("maintenance") or []:
        st = maintenance_status(m, now)
        end = parse_iso(m.get("endsAt")) if m.get("endsAt") else None
        if st == "completed" and end and now - end > timedelta(hours=24):
            continue
        maint.append({
            "id": m.get("id"), "title": m.get("title"), "reason": m.get("reason"),
            "startsAt": m.get("startsAt"), "endsAt": m.get("endsAt"),
            "affects": m.get("affects") or [], "status": st,
        })
    maint.sort(key=lambda m: str(m.get("startsAt") or ""))
    return maint


def manual_incidents(notices, components):
    """Los incidentes escritos a mano en el superadmin, con su historial de líneas."""
    names = {c["id"]: c["name"] for c in components}
    out = []
    for i in notices.get("incidents") or []:
        updates = [u for u in (i.get("updates") or []) if isinstance(u, dict) and u.get("text")]
        if not i.get("title"):
            continue
        out.append({
            "id": i.get("id"), "manual": True, "title": i.get("title"),
            "status": i.get("status") or "investigating",
            "start": i.get("startsAt"), "end": i.get("resolvedAt"),
            "ongoing": (i.get("status") or "") != "resolved",
            "components": [{"id": c, "name": names.get(c, {"es": c, "en": c})} for c in (i.get("affects") or [])],
            "updates": [{"at": u.get("at"), "status": u.get("status"), "text": u.get("text")} for u in updates],
        })
    out.sort(key=lambda i: str(i.get("start") or ""), reverse=True)
    return out


# ── Historia ────────────────────────────────────────────────────────────────

def append_history(state_dir, run):
    path = os.path.join(state_dir, "history.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(run, separators=(",", ":")) + "\n")


def load_history(state_dir, now, days=HISTORY_DAYS):
    path = os.path.join(state_dir, "history.jsonl")
    cutoff = now - timedelta(days=days)
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    t = parse_iso(r["t"])
                    if t and t >= cutoff:
                        rows.append(r)
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    return rows


def prune_history(state_dir, rows):
    """Reescribe la historia con sólo los 90 días (una vez al día basta)."""
    path = os.path.join(state_dir, "history.jsonl")
    write_atomic(path, "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))


def summarize(rows, components, now, days=HISTORY_DAYS, down_runs_for_day=5):
    ids = [c["id"] for c in components]
    windows = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "90d": timedelta(days=90)}
    uptime = {i: {} for i in ids}
    parsed = [(parse_iso(r["t"]), r) for r in rows]
    parsed = [(t, r) for t, r in parsed if t]
    for label, span in windows.items():
        if span.days > days:
            for i in ids:
                uptime[i][label] = None
            continue
        since = now - span
        for i in ids:
            total = up = 0
            for t, r in parsed:
                if t < since:
                    continue
                s = r["s"].get(i)
                if s is None:
                    continue
                total += 1
                if s != "down":
                    up += 1
            uptime[i][label] = round(100.0 * up / total, 3) if total else None

    # Barras diarias: el peor estado del día, con las corridas caídas.
    day_list = [(now - timedelta(days=n)).date() for n in range(days - 1, -1, -1)]
    daily = {i: [] for i in ids}
    by_day = {}
    for t, r in parsed:
        by_day.setdefault(t.date(), []).append(r)
    for i in ids:
        for day in day_list:
            runs = by_day.get(day, [])
            down = sum(1 for r in runs if r["s"].get(i) == "down")
            degraded = sum(1 for r in runs if r["s"].get(i) == "degraded")
            if not runs:
                state = "none"
            elif down >= down_runs_for_day:
                state = "down"
            elif down or degraded:
                state = "degraded"
            else:
                state = "ok"
            daily[i].append({"d": day.isoformat(), "s": state, "down": down})
    return uptime, daily


def incidents_from(rows, components, now, min_seconds=90):
    """Rachas de «down» consecutivas → incidentes automáticos (últimos 30 días)."""
    names = {c["id"]: c["name"] for c in components}
    since = now - timedelta(days=INCIDENT_DAYS)
    incidents = []
    current = None
    last_t = None
    for r in rows:
        t = parse_iso(r["t"])
        if not t:
            continue
        down = sorted(i for i, s in r["s"].items() if s == "down")
        if down:
            if current is None:
                current = {"start": t, "end": None, "components": set(down)}
            else:
                current["components"].update(down)
        elif current is not None:
            current["end"] = last_t or t
            incidents.append(current)
            current = None
        last_t = t
    if current is not None:
        incidents.append(current)
    out = []
    for inc in incidents:
        end = inc["end"]
        if end and end < since:
            continue
        dur = ((end or now) - inc["start"]).total_seconds()
        if dur < min_seconds and end is not None:
            continue  # un pestañeo de un minuto no es un incidente para los clientes
        out.append({
            "id": "auto-" + iso(inc["start"]), "manual": False,
            "start": iso(inc["start"]),
            "end": iso(end) if end else None,
            "ongoing": end is None,
            "minutes": int(round(dur / 60)),
            "components": [{"id": c, "name": names.get(c, {"es": c, "en": c})} for c in sorted(inc["components"])],
        })
    out.reverse()
    return out


def overall(results, maint, manual):
    in_maint = {c for m in maint if m["status"] == "in_progress" for c in (m.get("affects") or [])}
    down = [r for r in results if r["state"] == "down"]
    degraded = [r for r in results if r["state"] == "degraded"]
    if down and all(r["id"] in in_maint for r in down):
        return "maintenance"
    if down:
        return "major" if len(down) >= max(2, len(results) // 2) else "partial"
    if degraded:
        return "degraded"
    if any(i.get("ongoing") for i in manual):
        return "partial"
    if any(m["status"] == "in_progress" for m in maint):
        return "maintenance"
    return "ok"


# ── Avisos a la oficina (modo casa) y a Telegram (modo fuera) ───────────────

def hq_token():
    try:
        with open(HQ_ENV, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("HOOK_TOKEN="):
                    return line.strip().split("=", 1)[1]
    except Exception:
        return None
    return None


def hq_alert(token, severity, title, text):
    body = json.dumps({"kind": "alert", "severity": severity, "title": title, "text": text, "source": "cguard-status"}).encode()
    try:
        fetch(HQ_HOOK.format(token=token), 6, method="POST", data=body, headers={"Content-Type": "application/json"})
    except Exception:
        pass


def notify_transitions(state_dir, results, components, conf):
    """Aviso a IT (hook de la oficina): caído/recuperado al cambiar, y «lento»
    cuando lleva N minutos seguidos (y cuando deja de estarlo)."""
    path = os.path.join(state_dir, "last.json")
    last = read_json(path, {})
    # Compatibilidad con el fichero viejo ({id: state}).
    if last and "states" not in last:
        last = {"states": last}
    states = last.get("states") or {}
    slow_runs = last.get("slowRuns") or {}
    slow_alerted = last.get("slowAlerted") or {}
    names = {c["id"]: c["name"]["es"] for c in components}
    slow_after = int(conf.get("slow_alert_minutes", 5))
    msgs = []
    for r in results:
        cid = r["id"]
        prev = states.get(cid)
        if prev is not None and prev != r["state"] and ("down" in (prev, r["state"])):
            caido = r["state"] == "down"
            texto = (
                f"status.cguardpro.com: {names.get(cid, cid)} {'CAÍDO' if caido else 'recuperado'} ({r['detail']})"
                f"{' · el servidor responde en LAN: el problema es el túnel/borde' if r.get('lan') == 'ok' else ''}"
                f"{' · tampoco responde en LAN' if r.get('lan') == 'down' else ''}"
            )
            msgs.append(("high" if caido else "info", f"CGuard · {names.get(cid, cid)} {'caído' if caido else 'recuperado'}", texto))
        # Lento: cuenta corridas seguidas en «degraded».
        if r["state"] == "degraded":
            slow_runs[cid] = int(slow_runs.get(cid, 0)) + 1
            if slow_runs[cid] >= slow_after and not slow_alerted.get(cid):
                slow_alerted[cid] = True
                msgs.append(("medium", f"CGuard · {names.get(cid, cid)} lento", f"status.cguardpro.com: {names.get(cid, cid)} lleva {slow_runs[cid]} min respondiendo lento ({r['detail']})."))
        else:
            if slow_alerted.get(cid) and r["state"] == "ok":
                msgs.append(("info", f"CGuard · {names.get(cid, cid)} ya responde rápido", f"status.cguardpro.com: {names.get(cid, cid)} vuelve a responder a tiempo ({r['detail']})."))
            slow_runs[cid] = 0
            slow_alerted[cid] = False
    write_atomic(path, json.dumps({"states": {r["id"]: r["state"] for r in results}, "slowRuns": slow_runs, "slowAlerted": slow_alerted}))
    if not msgs:
        return
    token = hq_token()
    if not token:
        return
    for sev, title, text in msgs:
        hq_alert(token, sev, title, text)


def telegram(text):
    """Un mensaje al tema de Alertas de la oficina, directo a Telegram (sin la casa)."""
    tok = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat = os.environ.get("TELEGRAM_CHAT_ID")
    thread = os.environ.get("TELEGRAM_THREAD_ID")
    if not tok or not chat:
        print("telegram: sin credenciales; no se avisa", file=sys.stderr)
        return False
    payload = {"chat_id": chat, "text": text, "disable_web_page_preview": True}
    if thread:
        payload["message_thread_id"] = int(thread)
    code, body, _, err = fetch(f"https://api.telegram.org/bot{tok}/sendMessage", 10, method="POST",
                               data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    if code != 200:
        print(f"telegram: {err or code} {body[:120]}", file=sys.stderr)
    return code == 200


# ── Atom ────────────────────────────────────────────────────────────────────

def render_feed(data, conf):
    url = conf.get("public_url", "https://status.cguardpro.com").rstrip("/")
    names = {c["id"]: c["name"] for c in data["components"]}

    def nm(c):
        return c.get("name", {}).get("es", c.get("id")) if isinstance(c, dict) else str(c)

    entries = []
    for i in data["incidents"]:
        piezas = ", ".join(nm(c) for c in i.get("components") or [])
        if i.get("manual"):
            ups = i.get("updates") or []
            updated = (ups[-1]["at"] if ups else i.get("start")) or data["generatedAt"]
            estado = {"investigating": "Investigando", "identified": "Identificado", "monitoring": "Vigilando", "resolved": "Resuelto"}.get(i.get("status"), i.get("status"))
            lines = "".join(f"<p><b>{escape(str(u.get('at') or ''))}</b> · {escape(str(u.get('status') or ''))}: {escape(str(u.get('text') or ''))}</p>" for u in ups)
            entries.append((updated, f"[{estado}] {i['title']}", f"urn:cguard-status:incident:{i.get('id')}:{updated}",
                            f"<p>Afecta a: {escape(piezas) or '—'}</p>{lines}"))
        else:
            updated = i.get("end") or i.get("start") or data["generatedAt"]
            titulo = ("Caído / Down: " if i.get("ongoing") else "Recuperado / Recovered: ") + piezas
            entries.append((updated, titulo, f"urn:cguard-status:auto:{i.get('start')}:{'open' if i.get('ongoing') else 'closed'}",
                            f"<p>{escape(str(i.get('start')))} → {escape(str(i.get('end') or 'en curso'))} · {i.get('minutes', 0)} min</p>"))
    for m in data["maintenance"]:
        piezas = ", ".join(names.get(a, {}).get("es", a) if isinstance(names.get(a), dict) else a for a in (m.get("affects") or []))
        estado = {"scheduled": "Programado", "in_progress": "En curso", "completed": "Terminado"}.get(m.get("status"), m.get("status"))
        updated = m.get("endsAt") if m.get("status") == "completed" else (m.get("startsAt") or data["generatedAt"])
        entries.append((updated, f"[Mantenimiento · {estado}] {m.get('title')}", f"urn:cguard-status:maintenance:{m.get('id')}:{m.get('status')}",
                        f"<p>{escape(str(m.get('startsAt')))} → {escape(str(m.get('endsAt')))}</p><p>Afecta a: {escape(piezas) or '—'}</p>"
                        + (f"<p>{escape(str(m.get('reason')))}</p>" if m.get("reason") else "")))
    entries.sort(key=lambda e: str(e[0]), reverse=True)
    xml = ['<?xml version="1.0" encoding="utf-8"?>', '<feed xmlns="http://www.w3.org/2005/Atom">',
           '<title>Estado de CGuard Pro · CGuard Pro Status</title>', f'<id>{escape(url)}/</id>',
           f'<link rel="alternate" href="{escape(url)}/"/>', f'<link rel="self" href="{escape(url)}/feed.xml"/>',
           f'<updated>{escape(data["generatedAt"])}</updated>']
    for updated, title, eid, html in entries[:50]:
        xml.append(f'<entry><title>{escape(title)}</title><id>{escape(eid)}</id><updated>{escape(str(updated))}</updated>'
                   f'<link rel="alternate" href="{escape(url)}/"/><content type="html">{escape(html)}</content></entry>')
    xml.append('</feed>')
    return "\n".join(xml) + "\n"


# ── La página ──────────────────────────────────────────────────────────────

PAGE = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Estado de CGuard Pro</title>
<meta name="description" content="Estado en tiempo real de la plataforma CGuard Pro: CRM, API, apps, portal del cliente, panel de socios y radio.">
<meta http-equiv="refresh" content="300">
<link rel="alternate" type="application/atom+xml" title="Estado de CGuard Pro" href="feed.xml">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 2 4 7v9c0 7.5 5.1 12.4 12 14 6.9-1.6 12-6.5 12-14V7z' fill='%230ea5e9'/%3E%3C/svg%3E">
<style>
:root{--bg:#0b1220;--card:#111a2e;--line:#1f2a44;--fg:#e6edf7;--muted:#8b98b3;--ok:#22c55e;--warn:#f59e0b;--down:#ef4444;--maint:#38bdf8;--none:#2a3650}
@media (prefers-color-scheme: light){:root{--bg:#f5f7fb;--card:#fff;--line:#e3e8f0;--fg:#0f172a;--muted:#5b6b86;--none:#e3e8f0}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:28px 16px 56px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}.brand svg{width:26px;height:26px}
select.lang{background:var(--card);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:5px 8px;font-size:13px}
.hero{border-radius:14px;padding:18px 20px;color:#fff;display:flex;align-items:center;gap:14px;font-size:20px;font-weight:700}
.hero small{display:block;font-size:13px;font-weight:400;opacity:.9}
.hero.ok{background:#15803d}.hero.degraded{background:#b45309}.hero.partial{background:#b91c1c}.hero.major{background:#7f1d1d}.hero.maintenance{background:#0369a1}.hero.unknown{background:#475569}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-top:16px}
.note{border-left:4px solid var(--warn);padding:10px 14px;margin-top:16px;background:var(--card);border-radius:10px;font-size:14px}
.note.ok{border-left-color:var(--ok)}.note.bad{border-left-color:var(--down)}
h2{font-size:14px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}
.comp{display:grid;grid-template-columns:1fr auto;gap:6px 12px;padding:10px 0;border-top:1px solid var(--line)}.comp:first-of-type{border-top:0}
.comp .name{font-weight:600}.comp .state{display:flex;align-items:center;gap:8px;font-size:13px;white-space:nowrap}
.comp .ext{font-size:12px;color:var(--muted);grid-column:1/-1}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}.dot.ok{background:var(--ok)}.dot.degraded{background:var(--warn)}.dot.down{background:var(--down)}.dot.unknown{background:var(--none)}
.bars{grid-column:1/-1;display:grid;gap:2px;height:26px}
.bars i{border-radius:2px;background:var(--none)}.bars i.ok{background:var(--ok)}.bars i.degraded{background:var(--warn)}.bars i.down{background:var(--down)}
.up{grid-column:1/-1;display:flex;justify-content:space-between;font-size:12px;color:var(--muted);flex-wrap:wrap;gap:4px}
.m{padding:10px 0;border-top:1px solid var(--line)}.m:first-of-type{border-top:0}.m .t{font-weight:600}.m .d{color:var(--muted);font-size:13px}
.tl{margin:8px 0 0;padding:0;list-style:none}.tl li{font-size:13px;padding:4px 0 4px 14px;border-left:2px solid var(--line)}.tl li b{color:var(--fg)}.tl li span{color:var(--muted)}
.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:999px;margin-left:6px;vertical-align:middle;color:#fff}
.tag.scheduled{background:#475569}.tag.in_progress{background:var(--maint)}.tag.completed{background:#15803d}.tag.ongoing{background:var(--down)}
.tag.investigating{background:var(--down)}.tag.identified{background:#b45309}.tag.monitoring{background:#0369a1}.tag.resolved{background:#15803d}
form.sub{display:flex;gap:8px;flex-wrap:wrap}form.sub input{flex:1;min-width:200px;background:var(--bg);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:8px 10px;font-size:14px}
form.sub button{background:#0ea5e9;color:#fff;border:0;border-radius:8px;padding:8px 14px;font-weight:600;cursor:pointer}
.links{font-size:13px;color:var(--muted);margin-top:8px}.links a{color:var(--muted)}
footer{margin-top:28px;color:var(--muted);font-size:12px;text-align:center}footer a{color:var(--muted)}
.empty{color:var(--muted);font-size:14px}
@media (max-width:560px){.hero{font-size:17px}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="brand"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 4 7v9c0 7.5 5.1 12.4 12 14 6.9-1.6 12-6.5 12-14V7z" fill="#0ea5e9"/><path d="m11 16 3.2 3.2L21 12.5" stroke="#fff" stroke-width="2.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg><span data-i="title">Estado de CGuard Pro</span></div>
  <select class="lang" id="lang" aria-label="Idioma"></select>
</header>
<div id="app"><p class="empty" data-i="loading">Cargando…</p></div>
<footer><span data-i="footer">Se actualiza cada minuto desde un servidor independiente de la plataforma, y cada 5 minutos desde fuera.</span> · <span id="updated"></span><br><span id="backup"></span></footer>
</div>
<script id="data" type="application/json">__DATA__</script>
<script id="cfg" type="application/json">__CFG__</script>
<script>
(function(){
var I={
es:{title:"Estado de CGuard Pro",ok:"Todos los sistemas funcionan",degraded:"Rendimiento degradado",partial:"Interrupción parcial",major:"Interrupción mayor",maintenance:"Mantenimiento en curso",unknown:"Sin datos",
 subok:"Sin incidentes activos.",subdown:"Estamos trabajando en ello. Las apps de vigilante siguen fichando sin conexión.",
 components:"Componentes",maint:"Mantenimientos programados",incidents:"Incidentes de los últimos 30 días",noMaint:"No hay mantenimientos programados.",noInc:"Sin incidentes en los últimos 30 días.",
 s_ok:"Operativo",s_degraded:"Lento",s_down:"Caído",s_unknown:"Sin datos",scheduled:"Programado",in_progress:"En curso",completed:"Terminado",ongoing:"En curso",
 investigating:"Investigando",identified:"Identificado",monitoring:"Vigilando",resolved:"Resuelto",
 uptime:"Disponibilidad",days:"{n} días",min:"min",affects:"Afecta a",updated:"Actualizado",stale:"(aviso guardado; el API no contesta)",
 footer:"Se actualiza cada minuto desde un servidor independiente de la plataforma, y cada 5 minutos desde fuera.",duration:"Duración",loading:"Cargando…",
 outside:"Visto desde fuera",outsideOk:"responde",outsideDown:"no responde",outsideOld:"sin medida reciente",
 fallback:"Esta es la copia de respaldo, medida desde fuera de nuestra red: la página principal no responde. El historial largo no está disponible hasta que vuelva.",
 originStale:"La página principal lleva un rato sin actualizarse; estos datos pueden estar viejos.",
 subscribe:"Avísame por correo",subscribeHelp:"Un correo cuando se programe, empiece o termine un mantenimiento, y por cada actualización de un incidente. Te llegará un mensaje para confirmar.",subscribeBtn:"Suscribirme",subscribeSent:"Revisa tu correo y confirma la suscripción.",subscribeFail:"No se pudo enviar. Inténtalo en un momento.",email:"tu@correo.com",
 confirmada:"Suscripción confirmada: te avisaremos por correo.",baja:"Listo: ya no te enviaremos avisos.",invalida:"Ese enlace ya no vale. Vuelve a suscribirte si quieres avisos.",
 feed:"Suscribirse por RSS",backup:"Copia de respaldo fuera de nuestra red",primary:"Página principal"},
en:{title:"CGuard Pro Status",ok:"All systems operational",degraded:"Degraded performance",partial:"Partial outage",major:"Major outage",maintenance:"Maintenance in progress",unknown:"No data",
 subok:"No active incidents.",subdown:"We are on it. Guard apps keep clocking in offline.",
 components:"Components",maint:"Scheduled maintenance",incidents:"Incidents in the last 30 days",noMaint:"No scheduled maintenance.",noInc:"No incidents in the last 30 days.",
 s_ok:"Operational",s_degraded:"Slow",s_down:"Down",s_unknown:"No data",scheduled:"Scheduled",in_progress:"In progress",completed:"Completed",ongoing:"Ongoing",
 investigating:"Investigating",identified:"Identified",monitoring:"Monitoring",resolved:"Resolved",
 uptime:"Uptime",days:"{n} days",min:"min",affects:"Affects",updated:"Updated",stale:"(cached notice; the API is not answering)",
 footer:"Refreshed every minute from a server independent of the platform, and every 5 minutes from outside.",duration:"Duration",loading:"Loading…",
 outside:"Seen from outside",outsideOk:"responding",outsideDown:"not responding",outsideOld:"no recent measurement",
 fallback:"This is the backup copy, measured from outside our network: the main page is not responding. The long history is unavailable until it is back.",
 originStale:"The main page has not refreshed for a while; this data may be old.",
 subscribe:"Email me",subscribeHelp:"One email when maintenance is scheduled, starts or ends, and for every incident update. You will get a message to confirm.",subscribeBtn:"Subscribe",subscribeSent:"Check your inbox and confirm the subscription.",subscribeFail:"Could not send. Try again in a moment.",email:"you@example.com",
 confirmada:"Subscription confirmed: we will email you.",baja:"Done: no more notices will be sent.",invalida:"That link is no longer valid. Subscribe again if you want notices.",
 feed:"Subscribe via RSS",backup:"Backup copy outside our network",primary:"Main page"},
pt:{title:"Status da CGuard Pro",ok:"Todos os sistemas operando",degraded:"Desempenho degradado",partial:"Interrupção parcial",major:"Interrupção grave",maintenance:"Manutenção em andamento",unknown:"Sem dados",
 subok:"Sem incidentes ativos.",subdown:"Estamos trabalhando nisso. Os apps de vigilante continuam registrando ponto sem conexão.",
 components:"Componentes",maint:"Manutenções programadas",incidents:"Incidentes dos últimos 30 dias",noMaint:"Não há manutenções programadas.",noInc:"Sem incidentes nos últimos 30 dias.",
 s_ok:"Operacional",s_degraded:"Lento",s_down:"Fora do ar",s_unknown:"Sem dados",scheduled:"Programada",in_progress:"Em andamento",completed:"Concluída",ongoing:"Em andamento",
 investigating:"Investigando",identified:"Identificado",monitoring:"Monitorando",resolved:"Resolvido",
 uptime:"Disponibilidade",days:"{n} dias",min:"min",affects:"Afeta",updated:"Atualizado",stale:"(aviso guardado; a API não responde)",
 footer:"Atualizado a cada minuto de um servidor independente da plataforma, e a cada 5 minutos de fora.",duration:"Duração",loading:"Carregando…",
 outside:"Visto de fora",outsideOk:"responde",outsideDown:"não responde",outsideOld:"sem medição recente",
 fallback:"Esta é a cópia de reserva, medida de fora da nossa rede: a página principal não responde. O histórico longo fica indisponível até ela voltar.",
 originStale:"A página principal está há um tempo sem atualizar; estes dados podem estar velhos.",
 subscribe:"Avise-me por e-mail",subscribeHelp:"Um e-mail quando uma manutenção for programada, começar ou terminar, e a cada atualização de incidente. Você receberá uma mensagem para confirmar.",subscribeBtn:"Inscrever-me",subscribeSent:"Verifique seu e-mail e confirme a inscrição.",subscribeFail:"Não foi possível enviar. Tente novamente em instantes.",email:"voce@email.com",
 confirmada:"Inscrição confirmada: avisaremos por e-mail.",baja:"Pronto: não enviaremos mais avisos.",invalida:"Esse link não vale mais. Inscreva-se de novo se quiser avisos.",
 feed:"Assinar por RSS",backup:"Cópia de reserva fora da nossa rede",primary:"Página principal"},
fr:{title:"État de CGuard Pro",ok:"Tous les systèmes fonctionnent",degraded:"Performances dégradées",partial:"Panne partielle",major:"Panne majeure",maintenance:"Maintenance en cours",unknown:"Pas de données",
 subok:"Aucun incident en cours.",subdown:"Nous y travaillons. Les applications des agents continuent de pointer hors ligne.",
 components:"Composants",maint:"Maintenances programmées",incidents:"Incidents des 30 derniers jours",noMaint:"Aucune maintenance programmée.",noInc:"Aucun incident ces 30 derniers jours.",
 s_ok:"Opérationnel",s_degraded:"Lent",s_down:"En panne",s_unknown:"Pas de données",scheduled:"Programmée",in_progress:"En cours",completed:"Terminée",ongoing:"En cours",
 investigating:"En cours d'analyse",identified:"Cause identifiée",monitoring:"Sous surveillance",resolved:"Résolu",
 uptime:"Disponibilité",days:"{n} jours",min:"min",affects:"Concerne",updated:"Mis à jour",stale:"(avis en cache ; l'API ne répond pas)",
 footer:"Actualisé chaque minute depuis un serveur indépendant de la plateforme, et toutes les 5 minutes depuis l'extérieur.",duration:"Durée",loading:"Chargement…",
 outside:"Vu de l'extérieur",outsideOk:"répond",outsideDown:"ne répond pas",outsideOld:"pas de mesure récente",
 fallback:"Ceci est la copie de secours, mesurée hors de notre réseau : la page principale ne répond pas. L'historique long est indisponible jusqu'à son retour.",
 originStale:"La page principale ne s'est pas actualisée depuis un moment ; ces données peuvent être anciennes.",
 subscribe:"Me prévenir par e-mail",subscribeHelp:"Un e-mail quand une maintenance est programmée, commence ou se termine, et à chaque mise à jour d'incident. Vous recevrez un message pour confirmer.",subscribeBtn:"M'abonner",subscribeSent:"Consultez votre boîte mail et confirmez l'abonnement.",subscribeFail:"Envoi impossible. Réessayez dans un instant.",email:"vous@exemple.com",
 confirmada:"Abonnement confirmé : nous vous préviendrons par e-mail.",baja:"C'est fait : plus aucun avis ne sera envoyé.",invalida:"Ce lien n'est plus valable. Réabonnez-vous si vous voulez des avis.",
 feed:"S'abonner par RSS",backup:"Copie de secours hors de notre réseau",primary:"Page principale"},
de:{title:"Status von CGuard Pro",ok:"Alle Systeme laufen",degraded:"Eingeschränkte Leistung",partial:"Teilausfall",major:"Großer Ausfall",maintenance:"Wartung läuft",unknown:"Keine Daten",
 subok:"Keine aktiven Störungen.",subdown:"Wir arbeiten daran. Die Wächter-Apps stempeln offline weiter.",
 components:"Komponenten",maint:"Geplante Wartungen",incidents:"Störungen der letzten 30 Tage",noMaint:"Keine geplante Wartung.",noInc:"Keine Störungen in den letzten 30 Tagen.",
 s_ok:"Betriebsbereit",s_degraded:"Langsam",s_down:"Ausgefallen",s_unknown:"Keine Daten",scheduled:"Geplant",in_progress:"Läuft",completed:"Abgeschlossen",ongoing:"Laufend",
 investigating:"Wird untersucht",identified:"Ursache gefunden",monitoring:"Wird beobachtet",resolved:"Behoben",
 uptime:"Verfügbarkeit",days:"{n} Tage",min:"Min.",affects:"Betrifft",updated:"Aktualisiert",stale:"(gespeicherte Meldung; die API antwortet nicht)",
 footer:"Jede Minute von einem von der Plattform unabhängigen Server aktualisiert, und alle 5 Minuten von außen.",duration:"Dauer",loading:"Wird geladen…",
 outside:"Von außen gesehen",outsideOk:"antwortet",outsideDown:"antwortet nicht",outsideOld:"keine aktuelle Messung",
 fallback:"Dies ist die Sicherungskopie, von außerhalb unseres Netzes gemessen: die Hauptseite antwortet nicht. Der lange Verlauf ist erst wieder verfügbar, wenn sie zurück ist.",
 originStale:"Die Hauptseite wurde seit einer Weile nicht aktualisiert; diese Daten können veraltet sein.",
 subscribe:"Per E-Mail benachrichtigen",subscribeHelp:"Eine E-Mail, wenn eine Wartung geplant wird, beginnt oder endet, und bei jeder Störungsmeldung. Du bekommst eine Nachricht zur Bestätigung.",subscribeBtn:"Abonnieren",subscribeSent:"Prüfe dein Postfach und bestätige das Abonnement.",subscribeFail:"Senden nicht möglich. Versuche es gleich noch einmal.",email:"du@beispiel.de",
 confirmada:"Abonnement bestätigt: wir benachrichtigen dich per E-Mail.",baja:"Erledigt: es werden keine Meldungen mehr gesendet.",invalida:"Dieser Link gilt nicht mehr. Abonniere erneut, wenn du Meldungen willst.",
 feed:"Per RSS abonnieren",backup:"Sicherungskopie außerhalb unseres Netzes",primary:"Hauptseite"},
it:{title:"Stato di CGuard Pro",ok:"Tutti i sistemi funzionano",degraded:"Prestazioni ridotte",partial:"Interruzione parziale",major:"Interruzione grave",maintenance:"Manutenzione in corso",unknown:"Nessun dato",
 subok:"Nessun incidente attivo.",subdown:"Ci stiamo lavorando. Le app delle guardie continuano a timbrare offline.",
 components:"Componenti",maint:"Manutenzioni programmate",incidents:"Incidenti degli ultimi 30 giorni",noMaint:"Nessuna manutenzione programmata.",noInc:"Nessun incidente negli ultimi 30 giorni.",
 s_ok:"Operativo",s_degraded:"Lento",s_down:"Non disponibile",s_unknown:"Nessun dato",scheduled:"Programmata",in_progress:"In corso",completed:"Completata",ongoing:"In corso",
 investigating:"In analisi",identified:"Identificato",monitoring:"In osservazione",resolved:"Risolto",
 uptime:"Disponibilità",days:"{n} giorni",min:"min",affects:"Riguarda",updated:"Aggiornato",stale:"(avviso salvato; l'API non risponde)",
 footer:"Aggiornato ogni minuto da un server indipendente dalla piattaforma, e ogni 5 minuti dall'esterno.",duration:"Durata",loading:"Caricamento…",
 outside:"Visto dall'esterno",outsideOk:"risponde",outsideDown:"non risponde",outsideOld:"nessuna misura recente",
 fallback:"Questa è la copia di riserva, misurata fuori dalla nostra rete: la pagina principale non risponde. Lo storico lungo non è disponibile finché non torna.",
 originStale:"La pagina principale non si aggiorna da un po'; questi dati potrebbero essere vecchi.",
 subscribe:"Avvisami via e-mail",subscribeHelp:"Un'e-mail quando una manutenzione viene programmata, inizia o finisce, e a ogni aggiornamento di un incidente. Riceverai un messaggio per confermare.",subscribeBtn:"Iscrivimi",subscribeSent:"Controlla la posta e conferma l'iscrizione.",subscribeFail:"Invio non riuscito. Riprova tra un momento.",email:"tu@esempio.it",
 confirmada:"Iscrizione confermata: ti avviseremo via e-mail.",baja:"Fatto: non invieremo più avvisi.",invalida:"Questo link non è più valido. Iscriviti di nuovo se vuoi gli avvisi.",
 feed:"Iscriviti via RSS",backup:"Copia di riserva fuori dalla nostra rete",primary:"Pagina principale"},
nl:{title:"Status van CGuard Pro",ok:"Alle systemen werken",degraded:"Verminderde prestaties",partial:"Gedeeltelijke storing",major:"Grote storing",maintenance:"Onderhoud bezig",unknown:"Geen gegevens",
 subok:"Geen actieve storingen.",subdown:"We werken eraan. De bewakers-apps blijven offline inklokken.",
 components:"Onderdelen",maint:"Gepland onderhoud",incidents:"Storingen van de laatste 30 dagen",noMaint:"Geen gepland onderhoud.",noInc:"Geen storingen in de laatste 30 dagen.",
 s_ok:"Operationeel",s_degraded:"Traag",s_down:"Uitgevallen",s_unknown:"Geen gegevens",scheduled:"Gepland",in_progress:"Bezig",completed:"Afgerond",ongoing:"Bezig",
 investigating:"In onderzoek",identified:"Oorzaak gevonden",monitoring:"Onder observatie",resolved:"Opgelost",
 uptime:"Beschikbaarheid",days:"{n} dagen",min:"min",affects:"Betreft",updated:"Bijgewerkt",stale:"(opgeslagen melding; de API antwoordt niet)",
 footer:"Elke minuut bijgewerkt vanaf een server los van het platform, en elke 5 minuten van buitenaf.",duration:"Duur",loading:"Laden…",
 outside:"Van buitenaf gezien",outsideOk:"antwoordt",outsideDown:"antwoordt niet",outsideOld:"geen recente meting",
 fallback:"Dit is de reservekopie, gemeten buiten ons netwerk: de hoofdpagina antwoordt niet. De lange geschiedenis is niet beschikbaar tot ze terug is.",
 originStale:"De hoofdpagina is al een tijdje niet bijgewerkt; deze gegevens kunnen oud zijn.",
 subscribe:"Mail me",subscribeHelp:"Eén e-mail als onderhoud wordt gepland, begint of eindigt, en bij elke update van een storing. Je krijgt een bericht om te bevestigen.",subscribeBtn:"Inschrijven",subscribeSent:"Kijk in je mailbox en bevestig de inschrijving.",subscribeFail:"Versturen lukte niet. Probeer het zo opnieuw.",email:"jij@voorbeeld.nl",
 confirmada:"Inschrijving bevestigd: we mailen je.",baja:"Klaar: je krijgt geen meldingen meer.",invalida:"Die link is niet meer geldig. Schrijf je opnieuw in als je meldingen wilt.",
 feed:"Abonneren via RSS",backup:"Reservekopie buiten ons netwerk",primary:"Hoofdpagina"},
pl:{title:"Stan CGuard Pro",ok:"Wszystkie systemy działają",degraded:"Obniżona wydajność",partial:"Częściowa awaria",major:"Poważna awaria",maintenance:"Trwa konserwacja",unknown:"Brak danych",
 subok:"Brak aktywnych incydentów.",subdown:"Pracujemy nad tym. Aplikacje strażników nadal rejestrują czas offline.",
 components:"Składniki",maint:"Zaplanowane konserwacje",incidents:"Incydenty z ostatnich 30 dni",noMaint:"Brak zaplanowanych konserwacji.",noInc:"Brak incydentów w ostatnich 30 dniach.",
 s_ok:"Działa",s_degraded:"Wolno",s_down:"Nie działa",s_unknown:"Brak danych",scheduled:"Zaplanowana",in_progress:"W toku",completed:"Zakończona",ongoing:"W toku",
 investigating:"Badamy",identified:"Zidentyfikowano",monitoring:"Obserwujemy",resolved:"Rozwiązano",
 uptime:"Dostępność",days:"{n} dni",min:"min",affects:"Dotyczy",updated:"Zaktualizowano",stale:"(zapisany komunikat; API nie odpowiada)",
 footer:"Odświeżane co minutę z serwera niezależnego od platformy i co 5 minut z zewnątrz.",duration:"Czas trwania",loading:"Ładowanie…",
 outside:"Widok z zewnątrz",outsideOk:"odpowiada",outsideDown:"nie odpowiada",outsideOld:"brak aktualnego pomiaru",
 fallback:"To kopia zapasowa mierzona spoza naszej sieci: strona główna nie odpowiada. Dłuższa historia będzie niedostępna, dopóki nie wróci.",
 originStale:"Strona główna od jakiegoś czasu się nie odświeża; te dane mogą być nieaktualne.",
 subscribe:"Powiadom mnie e-mailem",subscribeHelp:"Jeden e-mail, gdy konserwacja zostanie zaplanowana, rozpocznie się lub zakończy, oraz przy każdej aktualizacji incydentu. Otrzymasz wiadomość do potwierdzenia.",subscribeBtn:"Zapisz mnie",subscribeSent:"Sprawdź pocztę i potwierdź subskrypcję.",subscribeFail:"Nie udało się wysłać. Spróbuj za chwilę.",email:"ty@przyklad.pl",
 confirmada:"Subskrypcja potwierdzona: będziemy pisać e-mailem.",baja:"Gotowe: nie będziemy już wysyłać powiadomień.",invalida:"Ten link już nie działa. Zapisz się ponownie, jeśli chcesz powiadomienia.",
 feed:"Subskrybuj przez RSS",backup:"Kopia zapasowa poza naszą siecią",primary:"Strona główna"}};
var NAMES={es:"Español",en:"English",pt:"Português",fr:"Français",de:"Deutsch",it:"Italiano",nl:"Nederlands",pl:"Polski"};
var LOCALE={es:"es-EC",en:"en-US",pt:"pt-BR",fr:"fr-FR",de:"de-DE",it:"it-IT",nl:"nl-NL",pl:"pl-PL"};
var CFG=JSON.parse(document.getElementById("cfg").textContent||"{}");
var langs=Object.keys(I);
var nav=(navigator.language||"es").slice(0,2).toLowerCase();
var L=localStorage.getItem("cgs-lang")||(langs.indexOf(nav)>=0?nav:"es");
var D=null;try{D=JSON.parse(document.getElementById("data").textContent)}catch(e){D=null}
var EXT=null,SRC=D?"origin":"none",ORIGIN_OLD=false;
var sel=document.getElementById("lang");langs.forEach(function(k){var o=document.createElement("option");o.value=k;o.textContent=NAMES[k];sel.appendChild(o)});sel.value=L;
function t(k){return (I[L]||I.es)[k]||I.es[k]||k}
function fmt(s){if(!s)return"";var d=new Date(s);if(isNaN(d))return String(s);return d.toLocaleString(LOCALE[L]||"es-EC",{dateStyle:"medium",timeStyle:"short"})}
function hm(s){if(!s)return"";var d=new Date(s);if(isNaN(d))return String(s);return d.toLocaleString(LOCALE[L]||"es-EC",{dateStyle:"short",timeStyle:"short"})}
function pct(v){return v==null?"—":(Math.round(v*100)/100).toFixed(2)+"%"}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function name(n){return n&&typeof n==="object"?(n[L]||n.en||n.es||""):String(n||"")}
function ageMin(s){var d=new Date(s);return isNaN(d)?1e9:(Date.now()-d.getTime())/60000}
function fromExternal(x){
 // La copia de fuera tiene la misma forma; sólo le faltan los 90 días.
 return {generatedAt:x.generatedAt,overall:x.overall,components:x.components,maintenance:x.maintenance||[],noticesStale:!!x.noticesStale,incidents:x.incidents||[],external:null,fallback:true};
}
function render(){
 document.documentElement.lang=L;
 document.querySelectorAll("[data-i]").forEach(function(e){e.textContent=t(e.getAttribute("data-i"))});
 if(!D){document.getElementById("app").innerHTML='<div class="hero unknown"><span>?</span><div>'+t("unknown")+'</div></div>';return}
 var o=D.overall||"unknown",h='<div class="hero '+o+'"><span>'+(o==="ok"?"✓":o==="maintenance"?"⚙":o==="unknown"?"?":"!")+'</span><div>'+t(o)+'<small>'+(o==="ok"?t("subok"):o==="maintenance"||o==="unknown"?"":t("subdown"))+'</small></div></div>';
 if(D.fallback)h+='<div class="note bad">'+t("fallback")+'</div>';
 else if(ORIGIN_OLD)h+='<div class="note">'+t("originStale")+'</div>';
 var q=new URLSearchParams(location.search).get("suscripcion");
 if(q&&I.es[q])h+='<div class="note '+(q==="invalida"?"bad":"ok")+'">'+t(q)+'</div>';
 var ext=(D.external&&D.external.components)||(EXT&&EXT.components?EXT.components.reduce(function(a,c){a[c.id]=c.state;return a},{}):null);
 var extAt=(D.external&&D.external.generatedAt)||(EXT&&EXT.generatedAt)||null;
 var extOld=extAt?ageMin(extAt)>20:true;
 h+='<div class="card"><h2>'+t("components")+'</h2>';
 D.components.forEach(function(c){
  var n=c.daily?c.daily.length:0;
  h+='<div class="comp"><div class="name">'+esc(name(c.name))+'</div><div class="state"><span class="dot '+c.state+'"></span>'+t("s_"+c.state)+'</div>';
  if(ext&&!D.fallback){var es=ext[c.id];h+='<div class="ext">'+t("outside")+': '+(extOld||!es?t("outsideOld"):(es==="down"?"✗ "+t("outsideDown"):"✓ "+t("outsideOk")))+'</div>'}
  if(n){h+='<div class="bars" style="grid-template-columns:repeat('+n+',1fr)">'+c.daily.map(function(d){return'<i class="'+d.s+'" title="'+d.d+(d.down?" · "+d.down+" "+t("min"):"")+'"></i>'}).join("")+'</div>';
   var u=c.uptime||{};h+='<div class="up"><span>'+t("days").replace("{n}",n)+'</span><span>'+t("uptime")+' 24h '+pct(u["24h"])+' · 7d '+pct(u["7d"])+(u["30d"]!=null?' · 30d '+pct(u["30d"]):"")+(u["90d"]!=null?' · 90d '+pct(u["90d"]):"")+'</span></div>'}
  h+='</div>';
 });
 h+='</div><div class="card"><h2>'+t("maint")+(D.noticesStale?' <span style="text-transform:none;letter-spacing:0">'+t("stale")+'</span>':"")+'</h2>';
 if(!D.maintenance.length)h+='<p class="empty">'+t("noMaint")+'</p>';
 D.maintenance.forEach(function(m){h+='<div class="m"><div class="t">'+esc(name(m.title))+'<span class="tag '+m.status+'">'+t(m.status)+'</span></div><div class="d">'+fmt(m.startsAt)+(m.endsAt?" → "+fmt(m.endsAt):"")+(m.affects&&m.affects.length?' · '+t("affects")+': '+m.affects.map(function(a){var c=D.components.filter(function(x){return x.id===a})[0];return esc(c?name(c.name):a)}).join(", "):"")+'</div>'+(m.reason?'<div class="d">'+esc(name(m.reason))+'</div>':"")+'</div>'});
 h+='</div><div class="card"><h2>'+t("incidents")+'</h2>';
 if(!D.incidents.length)h+='<p class="empty">'+t("noInc")+'</p>';
 D.incidents.forEach(function(i){
  var comps=i.components.map(function(c){return esc(name(c.name))}).join(", ");
  if(i.manual){
   h+='<div class="m"><div class="t">'+esc(i.title)+'<span class="tag '+i.status+'">'+t(i.status)+'</span></div><div class="d">'+fmt(i.start)+(i.end?" → "+fmt(i.end):"")+(comps?' · '+t("affects")+': '+comps:"")+'</div>';
   if(i.updates&&i.updates.length){h+='<ul class="tl">'+i.updates.slice().reverse().map(function(u){return'<li><b>'+t(u.status)+'</b> <span>'+hm(u.at)+'</span><br>'+esc(u.text)+'</li>'}).join("")+'</ul>'}
   h+='</div>';
  }else{
   h+='<div class="m"><div class="t">'+comps+(i.ongoing?'<span class="tag ongoing">'+t("ongoing")+'</span>':"")+'</div><div class="d">'+fmt(i.start)+(i.end?" → "+fmt(i.end):"")+' · '+t("duration")+' '+i.minutes+' '+t("min")+'</div></div>';
  }
 });
 h+='</div>';
 if(CFG.subscribe){h+='<div class="card"><h2>'+t("subscribe")+'</h2><p class="d" style="color:var(--muted);font-size:13px;margin:0 0 10px">'+t("subscribeHelp")+'</p><form class="sub" id="sub"><input type="email" required placeholder="'+esc(t("email"))+'" id="email" autocomplete="email"><button type="submit">'+t("subscribeBtn")+'</button></form><div id="submsg" class="d" style="margin-top:8px;font-size:13px"></div><div class="links"><a href="feed.xml">'+t("feed")+'</a></div></div>'}
 document.getElementById("app").innerHTML=h;
 document.getElementById("updated").textContent=t("updated")+" "+fmt(D.generatedAt);
 var b=document.getElementById("backup");
 if(CFG.self==="github"&&CFG.primary)b.innerHTML='<a href="'+esc(CFG.primary)+'">'+t("primary")+'</a>';
 else if(CFG.backup)b.innerHTML='<a href="'+esc(CFG.backup)+'">'+t("backup")+'</a>';
 var f=document.getElementById("sub");
 if(f)f.onsubmit=function(ev){ev.preventDefault();var em=document.getElementById("email").value;var msg=document.getElementById("submsg");msg.textContent="…";
  fetch(CFG.subscribe,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:em,locale:L})}).then(function(r){if(!r.ok)throw 0;msg.textContent=t("subscribeSent");f.reset()}).catch(function(){msg.textContent=t("subscribeFail")})};
}
function getJSON(url,ms){return new Promise(function(res,rej){var c=new AbortController();var to=setTimeout(function(){c.abort()},ms);fetch(url+(url.indexOf("?")<0?"?":"&")+"t="+Date.now(),{cache:"no-store",signal:c.signal}).then(function(r){clearTimeout(to);if(!r.ok)throw 0;return r.json()}).then(res,rej)})}
function load(){
 var originUrl=(CFG.origin?CFG.origin.replace(/\/$/,"")+"/":"")+"status.json";
 var pExt=CFG.external?getJSON(CFG.external,8000).catch(function(){return null}):Promise.resolve(null);
 return getJSON(originUrl,8000).then(function(j){return j},function(){return null}).then(function(j){
  return pExt.then(function(x){
   EXT=x;
   if(j&&ageMin(j.generatedAt)<=10){D=j;SRC="origin";ORIGIN_OLD=false}
   else if(j&&(!x||ageMin(j.generatedAt)<=ageMin(x.generatedAt))){D=j;SRC="origin";ORIGIN_OLD=true}
   else if(x){D=fromExternal(x);SRC="external"}
   else if(j){D=j;SRC="origin";ORIGIN_OLD=true}
   render();
  });
 });
}
sel.onchange=function(){L=sel.value;localStorage.setItem("cgs-lang",L);render()};
render();
if(!D)load();else if(CFG.external)load();
setInterval(load,60000);
})();
</script>
</body>
</html>
"""


def page_config(conf, self_kind):
    return {
        "self": self_kind,
        "origin": conf.get("origin_public_url") if self_kind == "github" else "",
        "external": conf.get("external_url"),
        "subscribe": conf.get("subscribe_url"),
        "backup": conf.get("backup_url"),
        "primary": conf.get("public_url"),
    }


def render_page(data, conf, self_kind="origin"):
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/") if data is not None else "null"
    cfg = json.dumps(page_config(conf, self_kind), ensure_ascii=False).replace("</", "<\\/")
    return PAGE.replace("__DATA__", payload).replace("__CFG__", cfg)


# ── Modo casa ───────────────────────────────────────────────────────────────

def load_external(conf):
    """La vista desde fuera (GitHub). Devuelve un resumen pequeño o None."""
    url = conf.get("external_url")
    if not url:
        return None
    code, body, _, err = fetch(url, 8)
    if code != 200:
        return None
    try:
        x = json.loads(body)
        return {
            "generatedAt": x.get("generatedAt"),
            "components": {c["id"]: c["state"] for c in x.get("components") or []},
            "overall": x.get("overall"),
        }
    except Exception:
        return None


def main_home():
    conf = read_json(CONF, None)
    if not conf:
        print(f"sin configuración en {CONF}", file=sys.stderr)
        return 2
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(OUT_DIR, exist_ok=True)
    now = now_utc()
    components = conf["components"]

    results = [probe(c, conf) for c in components]
    run = {"t": iso(now), "s": {r["id"]: r["state"] for r in results}}
    append_history(STATE_DIR, run)
    rows = load_history(STATE_DIR, now)
    if now.hour == 0 and now.minute < 2:
        prune_history(STATE_DIR, rows)

    notices, stale = load_notices(conf, os.path.join(STATE_DIR, "avisos.json"))
    maint = maintenance_list(notices, now)
    manual = manual_incidents(notices, components)
    external = load_external(conf)

    uptime, daily = summarize(rows, components, now)
    incidents = manual + incidents_from(rows, components, now)
    data = {
        "generatedAt": iso(now),
        "overall": overall(results, maint, manual),
        "components": [
            {
                "id": c["id"], "name": c["name"], "state": r["state"], "detail": r["detail"],
                "seconds": r["seconds"], "lan": r["lan"], "uptime": uptime[c["id"]], "daily": daily[c["id"]],
            }
            for c, r in zip(components, results)
        ],
        "maintenance": maint,
        "noticesStale": stale,
        "incidents": incidents,
        "external": external,
    }
    write_atomic(os.path.join(OUT_DIR, "status.json"), json.dumps(data, ensure_ascii=False))
    write_atomic(os.path.join(OUT_DIR, "feed.xml"), render_feed(data, conf))
    write_atomic(os.path.join(OUT_DIR, "index.html"), render_page(data, conf, "origin"))
    notify_transitions(STATE_DIR, results, components, conf)
    print(" ".join(f"{r['id']}={r['state']}" for r in results), "overall=" + data["overall"],
          "fuera=" + (external.get("overall", "?") if external else "sin datos"))
    return 0


# ── Modo fuera (GitHub Actions) ─────────────────────────────────────────────

def main_external(args):
    conf_path = args.get("--conf") or "components.public.json"
    state_path = args.get("--state") or "external.json"
    out_path = args.get("--out") or state_path
    conf = read_json(conf_path, None)
    if not conf:
        print(f"sin configuración en {conf_path}", file=sys.stderr)
        return 2
    now = now_utc()
    components = conf["components"]
    prev = read_json(state_path, {}) or {}
    runs = [r for r in (prev.get("runs") or []) if parse_iso(r.get("t")) and parse_iso(r["t"]) >= now - timedelta(days=EXTERNAL_HISTORY_DAYS)]
    alerts = prev.get("alerts") or {}

    results = [probe(c, conf) for c in components]
    runs.append({"t": iso(now), "s": {r["id"]: r["state"] for r in results}})

    notices, stale = load_notices(conf, None)
    if stale and prev.get("notices"):
        notices = prev["notices"]
    maint = maintenance_list(notices, now)
    manual = manual_incidents(notices, components)

    # ¿La página de la casa está viva y fresca?
    origin = {"reachable": False, "generatedAt": None, "fresh": False, "overall": None}
    ourl = (conf.get("origin_public_url") or "").rstrip("/")
    if ourl:
        code, body, _, err = fetch(ourl + "/status.json", 10)
        if code == 200:
            try:
                j = json.loads(body)
                g = parse_iso(j.get("generatedAt"))
                origin = {"reachable": True, "generatedAt": j.get("generatedAt"), "overall": j.get("overall"),
                          "fresh": bool(g and now - g <= timedelta(minutes=FRESH_MINUTES))}
            except Exception:
                origin["reachable"] = True

    # Dos corridas seguidas (10 min) para un incidente automático desde fuera.
    uptime, daily = summarize(runs, components, now, days=EXTERNAL_HISTORY_DAYS, down_runs_for_day=2)
    incidents = manual + incidents_from(runs, components, now, min_seconds=9 * 60)
    data = {
        "generatedAt": iso(now),
        "source": "github",
        "overall": overall(results, maint, manual),
        "components": [
            {"id": c["id"], "name": c["name"], "state": r["state"], "detail": r["detail"], "seconds": r["seconds"],
             "lan": None, "uptime": uptime[c["id"]], "daily": daily[c["id"]]}
            for c, r in zip(components, results)
        ],
        "maintenance": maint,
        "noticesStale": stale,
        "incidents": incidents,
        "origin": origin,
        "runs": runs,
        "notices": notices,
        "alerts": alerts,
    }

    # Avisos por Telegram, con memoria para no repetir.
    names = {c["id"]: c["name"]["es"] for c in components}
    public_url = conf.get("public_url", "https://status.cguardpro.com")
    msgs = []
    states = alerts.get("states") or {}
    for r in results:
        prev_state = states.get(r["id"])
        if prev_state is not None and prev_state != r["state"] and ("down" in (prev_state, r["state"])):
            caido = r["state"] == "down"
            msgs.append(f"{'🔴' if caido else '🟢'} CGuard desde fuera: {names.get(r['id'], r['id'])} {'CAÍDO' if caido else 'recuperado'} ({r['detail']})\n{public_url}")
    alerts["states"] = {r["id"]: r["state"] for r in results}
    stale_now = not origin["fresh"]
    if stale_now and not alerts.get("originStale"):
        # Se avisa a la segunda corrida seguida (10 min), no por un pestañeo.
        if alerts.get("originStaleSeen"):
            alerts["originStale"] = True
            msgs.append("🟠 status.cguardpro.com no se actualiza desde la casa"
                        + (f" (última actualización {origin['generatedAt']})" if origin.get("generatedAt") else " (no responde)")
                        + f". La copia de respaldo sigue midiendo desde fuera: {conf.get('backup_url', '')}")
        alerts["originStaleSeen"] = True
    elif not stale_now:
        if alerts.get("originStale"):
            msgs.append("🟢 status.cguardpro.com vuelve a actualizarse desde la casa.")
        alerts["originStale"] = False
        alerts["originStaleSeen"] = False
    data["alerts"] = alerts
    for m in msgs:
        telegram(m)

    write_atomic(out_path, json.dumps(data, ensure_ascii=False))
    print(" ".join(f"{r['id']}={r['state']}" for r in results), "overall=" + data["overall"],
          "casa=" + ("fresca" if origin["fresh"] else "vieja" if origin["reachable"] else "no responde"), f"avisos={len(msgs)}")
    return 0


def main():
    argv = sys.argv[1:]
    args = {}
    i = 0
    flags = []
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and i + 1 < len(argv) and not argv[i + 1].startswith("--"):
            args[a] = argv[i + 1]
            i += 2
        else:
            flags.append(a)
            i += 1
    if "--export-page" in flags:
        conf = read_json(args.get("--conf") or CONF, None) or {}
        sys.stdout.write(render_page(None, conf, "github"))
        return 0
    if "--external" in flags:
        return main_external(args)
    return main_home()


if __name__ == "__main__":
    sys.exit(main())
