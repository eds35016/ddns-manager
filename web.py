"""Flask web GUI: login-gated dashboard, full Cloudflare DNS record manager,
and live-editable settings.

Every route except /login and static assets requires an authenticated
session. All state-changing requests are CSRF-protected (flask-wtf). Core
flows work as plain form POST + redirect; static/app.js layers on modals,
polling, and toasts.
"""

import csv
import functools
import io
import ipaddress
import json
import logging
import re
import threading
import time
from datetime import timedelta
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from werkzeug.security import check_password_hash, generate_password_hash

import cloudflare_client as cf
import config_store
import ip_history
import poller

log = logging.getLogger(__name__)

# Dummy hash so login always runs one check_password_hash — a wrong username
# costs the same time as a wrong password.
_DUMMY_HASH = generate_password_hash("incorrect-placeholder")

# --- login rate limiting (in-memory, per client IP) -------------------------
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
_attempts = {}  # ip -> {"count": int, "locked_until": float}
_attempts_lock = threading.Lock()

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*"
    r"[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.?$"
)

TTL_CHOICES = [1, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 28800, 86400]

FORM_RECORD_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA"]

HISTORY_PAGE_SIZE = 20


def _history_family():
    """Validated ?family= filter — 'IPv4', 'IPv6', or None for all."""
    fam = request.args.get("family", "")
    return fam if fam in ("IPv4", "IPv6") else None


def _client_ip():
    return request.remote_addr or "unknown"


def _is_locked_out(ip):
    with _attempts_lock:
        entry = _attempts.get(ip)
        if not entry:
            return False
        if entry.get("locked_until", 0) > time.time():
            return True
        if entry.get("locked_until", 0):
            del _attempts[ip]
        return False


def _record_failed_attempt(ip):
    with _attempts_lock:
        entry = _attempts.setdefault(ip, {"count": 0, "locked_until": 0})
        entry["count"] += 1
        if entry["count"] >= MAX_ATTEMPTS:
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS
            entry["count"] = 0
            log.warning("Login locked out for %s after repeated failures", ip)


def _clear_attempts(ip):
    with _attempts_lock:
        _attempts.pop(ip, None)


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("authenticated"):
            return view(*args, **kwargs)
        if request.path.startswith("/api/"):
            return jsonify({"error": "auth"}), 401
        return redirect(url_for("login", next=request.path))
    return wrapped


def _safe_next(target):
    """Only allow same-app path redirects — no scheme, no netloc, no //."""
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return None
    return target


# --- validation helpers ------------------------------------------------------

def _valid_hostname(name):
    return bool(name) and bool(HOSTNAME_RE.match(name))


def _valid_ttl(ttl):
    return ttl == 1 or 30 <= ttl <= 86400


def _int_field(form, key, label, errors, lo=None, hi=None, default=None):
    raw = form.get(key, "").strip()
    if raw == "" and default is not None:
        return default
    try:
        value = int(raw)
    except ValueError:
        errors.append(f"{label} must be a number.")
        return None
    if lo is not None and value < lo or hi is not None and value > hi:
        errors.append(f"{label} must be between {lo} and {hi}.")
        return None
    return value


def _build_record_payload(form):
    """Validate the record form and build the Cloudflare API payload.

    Returns (payload, errors). On errors, payload is None.
    """
    errors = []
    rtype = form.get("type", "").strip().upper()
    name = form.get("name", "").strip()
    ttl = _int_field(form, "ttl", "TTL", errors, default=1)
    proxied = form.get("proxied") == "on"

    if rtype not in FORM_RECORD_TYPES and rtype != "OTHER":
        errors.append("Unknown record type.")
        return None, errors
    if rtype != "OTHER" and not _valid_hostname(name):
        errors.append("Record name must be a valid hostname (use @ handling via the full domain name).")
    if ttl is not None and not _valid_ttl(ttl):
        errors.append("TTL must be Auto or between 30 and 86400 seconds.")

    payload = {"name": name, "ttl": ttl if ttl is not None else 1}

    if rtype in cf.PROXYABLE_TYPES:
        payload["proxied"] = proxied
        if proxied:
            payload["ttl"] = 1  # Cloudflare forces Auto TTL on proxied records
    elif proxied:
        errors.append(f"{rtype} records cannot be proxied.")

    content = form.get("content", "").strip()

    if rtype == "A":
        try:
            addr = ipaddress.ip_address(content)
            if addr.version != 4:
                raise ValueError
            payload.update(type="A", content=str(addr))
        except ValueError:
            errors.append("A record content must be a valid IPv4 address.")
    elif rtype == "AAAA":
        try:
            addr = ipaddress.ip_address(content)
            if addr.version != 6:
                raise ValueError
            payload.update(type="AAAA", content=str(addr))
        except ValueError:
            errors.append("AAAA record content must be a valid IPv6 address.")
    elif rtype == "CNAME":
        if not _valid_hostname(content):
            errors.append("CNAME target must be a valid hostname.")
        payload.update(type="CNAME", content=content)
    elif rtype == "TXT":
        if not content:
            errors.append("TXT record content cannot be empty.")
        payload.update(type="TXT", content=content)
    elif rtype == "MX":
        priority = _int_field(form, "priority", "Priority", errors, 0, 65535, default=10)
        if not _valid_hostname(content):
            errors.append("MX content must be a valid mail server hostname.")
        payload.update(type="MX", content=content, priority=priority)
    elif rtype == "SRV":
        # Service/proto live in the record name (_sip._tcp.example.com);
        # Cloudflare derives content from data.
        payload.pop("proxied", None)
        data = {
            "priority": _int_field(form, "srv_priority", "SRV priority", errors, 0, 65535, default=1),
            "weight": _int_field(form, "srv_weight", "SRV weight", errors, 0, 65535, default=1),
            "port": _int_field(form, "srv_port", "SRV port", errors, 1, 65535),
            "target": form.get("srv_target", "").strip(),
        }
        if not _valid_hostname(data["target"] or ""):
            errors.append("SRV target must be a valid hostname.")
        if not name.startswith("_"):
            errors.append("SRV record name must include service and protocol, e.g. _minecraft._tcp.example.com")
        payload.update(type="SRV", data=data)
    elif rtype == "CAA":
        tag = form.get("caa_tag", "issue").strip()
        value = form.get("caa_value", "").strip()
        if tag not in ("issue", "issuewild", "iodef"):
            errors.append("CAA tag must be issue, issuewild, or iodef.")
        if not value:
            errors.append("CAA value cannot be empty.")
        payload.update(type="CAA", data={
            "flags": _int_field(form, "caa_flags", "CAA flags", errors, 0, 255, default=0),
            "tag": tag, "value": value,
        })
    elif rtype == "OTHER":
        raw_type = form.get("other_type", "").strip().upper()
        raw_json = form.get("other_json", "").strip()
        if not re.fullmatch(r"[A-Z]{1,12}", raw_type or ""):
            errors.append("Record type must be letters only (e.g. NS, PTR, LOC).")
        try:
            extra = json.loads(raw_json) if raw_json else {}
            if not isinstance(extra, dict):
                raise ValueError
        except ValueError:
            errors.append("Advanced JSON must be a valid JSON object.")
            extra = {}
        payload["type"] = raw_type
        payload.update(extra)  # advanced field may override any key except type
        payload["type"] = raw_type
        if not _valid_hostname(payload.get("name", "")):
            errors.append("Record name must be a valid hostname.")

    if errors:
        return None, errors
    return payload, []


def _fmt_cf_error(exc):
    if exc.code:
        return f"Cloudflare error {exc.code}: {exc.message}"
    return exc.message


# --- app factory --------------------------------------------------------------

def create_app():
    config = config_store.get_config()

    app = Flask(__name__)
    app.secret_key = config["session_secret"]
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    CSRFProtect(app)

    @app.template_filter("ts")
    def fmt_ts(value):
        if not value:
            return "never"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        # For fetch() endpoints return JSON so app.js can react (the usual
        # cause is an expired session); browsers get the normal error page.
        if request.path.startswith("/api/"):
            return jsonify({"error": "csrf", "message": e.description}), 400
        flash("Your session expired — please try again.", "error")
        return redirect(url_for("login"))

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        if session.get("authenticated"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # --- auth -----------------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("authenticated"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            ip = _client_ip()
            if _is_locked_out(ip):
                flash("Too many failed attempts. Try again in a few minutes.", "error")
                return render_template("login.html"), 429

            cfg = config_store.get_config()
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            stored_hash = cfg["admin_password_hash"] \
                if username == cfg["admin_username"] else _DUMMY_HASH
            ok = check_password_hash(stored_hash, password) \
                and username == cfg["admin_username"]

            if ok:
                _clear_attempts(ip)
                session.clear()  # new session identity on login (fixation)
                session["authenticated"] = True
                session.permanent = True
                target = _safe_next(request.args.get("next"))
                return redirect(target or url_for("dashboard"))

            _record_failed_attempt(ip)
            flash("Incorrect username or password.", "error")
            return render_template("login.html"), 401

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # --- dashboard --------------------------------------------------------------

    @app.route("/")
    @login_required
    def dashboard():
        cfg = config_store.get_config()
        state = config_store.get_state()
        family = _history_family()
        history, history_more = ip_history.get_page(
            limit=HISTORY_PAGE_SIZE, family=family)
        return render_template(
            "dashboard.html", state=state,
            tracked_count=len(cfg.get("ddns_tracked_record_ids", [])),
            poll_interval=cfg.get("poll_interval_seconds", 300),
            configured=bool(cfg.get("cloudflare_api_token")
                            and cfg.get("cloudflare_zone_id")),
            history=history, history_more=history_more,
            history_family=family,
        )

    @app.route("/api/status")
    @login_required
    def api_status():
        state = config_store.get_state()
        cfg = config_store.get_config()
        return jsonify({
            "last_ipv4": state.get("last_ipv4"),
            "last_ipv6": state.get("last_ipv6"),
            "last_check_ts": state.get("last_check_ts"),
            "last_change_ts": state.get("last_change_ts"),
            "cloudflare_auth_ok": state.get("cloudflare_auth_ok", True),
            "cloudflare_error": state.get("cloudflare_error"),
            "alerts": {k: v for k, v in state.get("alerts", {}).items() if v},
            "records": state.get("records", {}),
            "notify": state.get("notify", {}),
            "poll_interval": cfg.get("poll_interval_seconds", 300),
        })

    @app.route("/api/check-now", methods=["POST"])
    @login_required
    def api_check_now():
        poller.wake_event.set()
        return jsonify({"ok": True})

    @app.route("/api/ip-history")
    @login_required
    def api_ip_history():
        before = request.args.get("before", "")
        before_id = int(before) if before.isdigit() else None
        entries, has_more = ip_history.get_page(
            before_id=before_id, limit=HISTORY_PAGE_SIZE,
            family=_history_family())
        return jsonify({"entries": entries, "has_more": has_more})

    @app.route("/ip-history.csv")
    @login_required
    def ip_history_csv():
        def fmt(ts):
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) \
                if ts else ""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["family", "ip", "active_from", "active_until",
                         "active_from_epoch", "active_until_epoch"])
        for row in ip_history.get_all():
            writer.writerow([row["family"], row["ip"], fmt(row["started_ts"]),
                             fmt(row["ended_ts"]) or "active",
                             row["started_ts"], row["ended_ts"] or ""])
        return Response(buf.getvalue(), mimetype="text/csv", headers={
            "Content-Disposition": "attachment; filename=ip-history.csv"})

    # --- DNS records ------------------------------------------------------------

    @app.route("/records")
    @login_required
    def records():
        cfg = config_store.get_config()
        if not cfg.get("cloudflare_api_token") or not cfg.get("cloudflare_zone_id"):
            return render_template("records.html", records=None,
                                   cf_error=None, unconfigured=True,
                                   tracked_ids=set(), ttl_choices=TTL_CHOICES)
        try:
            zone_records = cf.list_dns_records(
                cfg["cloudflare_api_token"], cfg["cloudflare_zone_id"])
            cf_error = None
        except cf.CloudflareError as exc:
            zone_records = None
            cf_error = _fmt_cf_error(exc)
        return render_template(
            "records.html", records=zone_records, cf_error=cf_error,
            unconfigured=False,
            tracked_ids=set(cfg.get("ddns_tracked_record_ids", [])),
            ttl_choices=TTL_CHOICES,
        )

    @app.route("/records/create", methods=["POST"])
    @login_required
    def records_create():
        payload, errors = _build_record_payload(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("records"))
        cfg = config_store.get_config()
        try:
            record = cf.create_dns_record(
                cfg["cloudflare_api_token"], cfg["cloudflare_zone_id"], payload)
            flash(f"Created {record['type']} record {record['name']}.", "success")
        except cf.CloudflareError as exc:
            flash(f"Create failed — {_fmt_cf_error(exc)}", "error")
        return redirect(url_for("records"))

    @app.route("/records/<record_id>/update", methods=["POST"])
    @login_required
    def records_update(record_id):
        if not re.fullmatch(r"[a-f0-9]{32}", record_id):
            abort(404)
        payload, errors = _build_record_payload(request.form)
        if errors:
            for e in errors:
                flash(e, "error")
            return redirect(url_for("records"))
        cfg = config_store.get_config()
        try:
            record = cf.update_dns_record_full(
                cfg["cloudflare_api_token"], cfg["cloudflare_zone_id"],
                record_id, payload)
            flash(f"Updated {record['type']} record {record['name']}.", "success")
        except cf.CloudflareError as exc:
            flash(f"Update failed — {_fmt_cf_error(exc)}", "error")
        return redirect(url_for("records"))

    @app.route("/records/<record_id>/delete", methods=["POST"])
    @login_required
    def records_delete(record_id):
        if not re.fullmatch(r"[a-f0-9]{32}", record_id):
            abort(404)
        cfg = config_store.get_config()
        try:
            cf.delete_dns_record(
                cfg["cloudflare_api_token"], cfg["cloudflare_zone_id"], record_id)
            tracked = [r for r in cfg.get("ddns_tracked_record_ids", [])
                       if r != record_id]
            config_store.update_config({"ddns_tracked_record_ids": tracked})
            flash("Record deleted.", "success")
        except cf.CloudflareError as exc:
            flash(f"Delete failed — {_fmt_cf_error(exc)}", "error")
        return redirect(url_for("records"))

    @app.route("/records/<record_id>/toggle-ddns", methods=["POST"])
    @login_required
    def records_toggle_ddns(record_id):
        if not re.fullmatch(r"[a-f0-9]{32}", record_id):
            abort(404)
        cfg = config_store.get_config()
        tracked = list(cfg.get("ddns_tracked_record_ids", []))
        if record_id in tracked:
            tracked.remove(record_id)
            flash("Record removed from DDNS auto-update.", "success")
        else:
            tracked.append(record_id)
            flash("Record will now be kept updated with your public IP.", "success")
        config_store.update_config({"ddns_tracked_record_ids": tracked})
        poller.wake_event.set()
        return redirect(url_for("records"))

    # --- settings ---------------------------------------------------------------

    def _mask_webhook(url):
        """Show enough of a saved webhook to recognize it, never the token."""
        tail = url.rstrip("/").rsplit("/", 2)
        wid = tail[-2] if len(tail) >= 2 else "?"
        return f"…/webhooks/{wid}/…{url[-4:]}"

    def _parse_discord_user_ids(raw, errors):
        """Parse a comma/space-separated list of Discord user IDs (snowflakes)."""
        ids = []
        for part in re.split(r"[,\s]+", raw.strip()):
            if not part:
                continue
            if not re.fullmatch(r"\d{15,25}", part):
                errors.append(f"Not a valid Discord user ID: {part}")
            elif part not in ids:
                ids.append(part)
        return ids

    @app.route("/settings")
    @login_required
    def settings():
        cfg = config_store.get_config()
        return render_template(
            "settings.html",
            cfg=cfg,
            has_token=bool(cfg.get("cloudflare_api_token")),
            webhooks=[{"masked": _mask_webhook(w["url"]),
                       "ping_user_ids": ", ".join(w.get("ping_user_ids", []))}
                      for w in cfg.get("discord_webhook_urls", [])],
            to_addrs_joined=", ".join(cfg.get("smtp", {}).get("to_addrs", [])),
            has_smtp_password=bool(cfg.get("smtp", {}).get("password")),
        )

    @app.route("/settings/save", methods=["POST"])
    @login_required
    def settings_save():
        form = request.form
        cfg = config_store.get_config()
        errors = []
        changes = {}

        interval = _int_field(form, "poll_interval_seconds", "Poll interval",
                              errors, 60, 86400)
        if interval is not None:
            changes["poll_interval_seconds"] = interval

        zone_id = form.get("cloudflare_zone_id", "").strip()
        if zone_id and not re.fullmatch(r"[a-f0-9]{32}", zone_id):
            errors.append("Zone ID should be the 32-character hex ID from the Cloudflare dashboard.")
        else:
            changes["cloudflare_zone_id"] = zone_id

        # Secrets: blank means keep the existing value.
        token = form.get("cloudflare_api_token", "").strip()
        if token:
            changes["cloudflare_api_token"] = token

        # Discord webhooks: keep the saved list minus any checked for removal
        # (picking up each row's edited ping user IDs along the way), then
        # append new ones (textarea, one per line).
        webhooks = list(cfg.get("discord_webhook_urls", []))
        remove_idx = {int(i) for i in form.getlist("remove_webhook")
                      if i.isdigit()}
        ping_id_inputs = form.getlist("webhook_ping_ids")
        kept_webhooks = []
        existing_urls = set()
        for i, w in enumerate(webhooks):
            if i in remove_idx:
                continue
            raw_ids = ping_id_inputs[i] if i < len(ping_id_inputs) else ""
            kept_webhooks.append({"url": w["url"],
                                  "ping_user_ids": _parse_discord_user_ids(raw_ids, errors)})
            existing_urls.add(w["url"])
        for line in form.get("new_webhooks", "").splitlines():
            line = line.strip()
            if not line:
                continue
            url, _, raw_ids = line.partition(" ")
            if not url.startswith("https://discord.com/api/webhooks/") and \
               not url.startswith("https://discordapp.com/api/webhooks/"):
                errors.append(f"Not a Discord webhook URL: {url[:40]}…")
            elif url not in existing_urls:
                kept_webhooks.append({"url": url,
                                      "ping_user_ids": _parse_discord_user_ids(raw_ids, errors)})
                existing_urls.add(url)
        changes["discord_webhook_urls"] = kept_webhooks

        smtp_changes = {}
        smtp_host = form.get("smtp_host", "").strip()
        smtp_changes["host"] = smtp_host
        port = _int_field(form, "smtp_port", "SMTP port", errors, 1, 65535, default=587)
        if port is not None:
            smtp_changes["port"] = port
        security = form.get("smtp_security", "starttls")
        if security not in ("starttls", "ssl", "none"):
            errors.append("SMTP security must be STARTTLS, SSL, or none.")
        else:
            smtp_changes["security"] = security
        smtp_changes["username"] = form.get("smtp_username", "").strip()
        smtp_password = form.get("smtp_password", "")
        if smtp_password:
            smtp_changes["password"] = smtp_password
        from_addr = form.get("smtp_from_addr", "").strip()
        if from_addr and ("@" not in from_addr or " " in from_addr):
            errors.append("From address must be a valid email address.")
        else:
            smtp_changes["from_addr"] = from_addr

        # Recipients: comma- or newline-separated list.
        to_addrs = []
        for part in re.split(r"[,\n]", form.get("smtp_to_addrs", "")):
            addr = part.strip()
            if not addr:
                continue
            if "@" not in addr or " " in addr:
                errors.append(f"Not a valid email address: {addr}")
            elif addr not in to_addrs:
                to_addrs.append(addr)
        smtp_changes["to_addrs"] = to_addrs

        changes["smtp"] = smtp_changes
        changes["notify_ipv4_changes"] = form.get("notify_ipv4_changes") == "on"
        changes["notify_ipv6_changes"] = form.get("notify_ipv6_changes") == "on"
        changes["notify_on_errors"] = form.get("notify_on_errors") == "on"

        if errors:
            for e in errors:
                flash(e, "error")
        else:
            config_store.update_config(changes)
            poller.wake_event.set()
            flash("Settings saved — changes take effect immediately.", "success")
        return redirect(url_for("settings"))

    @app.route("/settings/password", methods=["POST"])
    @login_required
    def settings_password():
        cfg = config_store.get_config()
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not check_password_hash(cfg["admin_password_hash"], current):
            flash("Current password is incorrect.", "error")
        elif len(new) < 10:
            flash("New password must be at least 10 characters.", "error")
        elif new != confirm:
            flash("New passwords don't match.", "error")
        else:
            config_store.update_config(
                {"admin_password_hash": generate_password_hash(new)})
            flash("Password changed.", "success")
        return redirect(url_for("settings"))

    @app.route("/settings/test-connection", methods=["POST"])
    @login_required
    def settings_test_connection():
        cfg = config_store.get_config()
        if not cfg.get("cloudflare_api_token"):
            flash("Add your Cloudflare API token first.", "error")
            return redirect(url_for("settings"))
        try:
            status = cf.verify_token(cfg["cloudflare_api_token"])
            if cfg.get("cloudflare_zone_id"):
                records = cf.list_dns_records(
                    cfg["cloudflare_api_token"], cfg["cloudflare_zone_id"])
                flash(f"Connection OK — token is {status}, zone has "
                      f"{len(records)} DNS record(s).", "success")
            else:
                flash(f"Token is {status}, but no Zone ID is set yet.", "success")
        except cf.CloudflareError as exc:
            flash(f"Connection failed — {_fmt_cf_error(exc)}", "error")
        return redirect(url_for("settings"))

    return app
