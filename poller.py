"""DDNS poller: detect public IP changes, update tracked Cloudflare records,
notify via Discord webhook and email.

Cloudflare is optional: with no API token/zone/tracked records configured the
service runs in notification-only mode — IP changes still trigger Discord and
email alerts, they just don't update any DNS records.

Runs as a daemon thread. Sleeps on wake_event.wait(timeout=interval) so the
web GUI can wake it instantly ("Check Now", settings save) — this is what
makes config changes take effect without a service restart. A separate
stop_event signals shutdown.
"""

import ipaddress
import logging
import smtplib
import threading
import time
from email.message import EmailMessage

import requests

import cloudflare_client as cf
import config_store
import ip_history
import summary

log = logging.getLogger(__name__)

# Signals the poller to run a cycle immediately (Check Now / settings save).
wake_event = threading.Event()
# Signals the poller to exit.
stop_event = threading.Event()

IPV4_SOURCES = ["https://api.ipify.org", "https://ipv4.icanhazip.com"]
IPV6_SOURCES = ["https://api6.ipify.org", "https://ipv6.icanhazip.com"]

DISCORD_MESSAGE_LIMIT = 2000

# After a Cloudflare API failure the fast path can't know what state the
# records were left in, so the next cycle does a full reconcile.
_needs_reconcile = True


def request_reconcile():
    """Ask the poller for a full reconcile on its next cycle, then wake it.

    Used by the web GUI whenever the tracked-record set or Cloudflare
    settings change, and by "Check now" — the public IP usually hasn't
    changed at those moments, so a plain wake would skip the records."""
    global _needs_reconcile
    _needs_reconcile = True
    wake_event.set()


def _fetch_ip(sources, family_check):
    """Try each source in order; return a validated IP string or None."""
    for url in sources:
        try:
            resp = requests.get(url, timeout=(5, 10))
            resp.raise_for_status()
            candidate = resp.text.strip()
            addr = ipaddress.ip_address(candidate)
            if family_check(addr):
                return str(addr)
            log.warning("%s returned wrong address family: %s", url, candidate)
        except (requests.RequestException, ValueError) as exc:
            log.debug("IP lookup via %s failed: %s", url, exc)
    return None


def get_public_ips():
    """Return (ipv4, ipv6); either may be None. Values are validated with
    ipaddress so a captive portal's HTML can never end up in a DNS record."""
    ipv4 = _fetch_ip(IPV4_SOURCES, lambda a: a.version == 4)
    ipv6 = _fetch_ip(IPV6_SOURCES, lambda a: a.version == 6)
    return ipv4, ipv6


def send_discord_notification(webhook_url, message, ping_user_ids=None):
    if ping_user_ids:
        mentions = " ".join(f"<@{uid}>" for uid in ping_user_ids)
        message = f"{mentions}\n{message}"
    if len(message) > DISCORD_MESSAGE_LIMIT:
        message = message[: DISCORD_MESSAGE_LIMIT - 25] + "\n… (message truncated)"
    resp = requests.post(webhook_url, json={"content": message}, timeout=(5, 10))
    resp.raise_for_status()


def send_email_notification(smtp_cfg, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_cfg["from_addr"]
    msg["To"] = ", ".join(smtp_cfg["to_addrs"])
    msg.set_content(body)

    host, port = smtp_cfg["host"], int(smtp_cfg["port"])
    security = smtp_cfg.get("security", "starttls")
    if security == "ssl":
        server = smtplib.SMTP_SSL(host, port, timeout=10)
    else:
        server = smtplib.SMTP(host, port, timeout=10)
    try:
        if security == "starttls":
            server.starttls()
        if smtp_cfg.get("username"):
            server.login(smtp_cfg["username"], smtp_cfg["password"])
        server.send_message(msg)
    finally:
        server.quit()


def build_notification_message(old_ipv4, new_ipv4, old_ipv6, new_ipv6, results):
    """One shared summary for both channels so they never disagree.

    An empty results list means notify-only mode (no Cloudflare records
    tracked) — the message then carries just the IP change itself."""
    lines = ["**Public IP address change detected**"]
    if new_ipv4 and old_ipv4 != new_ipv4:
        lines.append(f"IPv4: {old_ipv4 or 'unknown'} → {new_ipv4}")
    if new_ipv6 and old_ipv6 != new_ipv6:
        lines.append(f"IPv6: {old_ipv6 or 'unknown'} → {new_ipv6}")
    if not results:
        lines.append("")
        lines.append("No DNS records are set up for automatic updates "
                     "(notification-only mode).")
        return "\n".join(lines)
    lines.append("")
    ok = [r for r in results if r["ok"]]
    failed = [r for r in results if not r["ok"]]
    lines.append(f"DNS updates: {len(ok)} succeeded, {len(failed)} failed")
    for r in results:
        mark = "✅" if r["ok"] else "❌"
        detail = "" if r["ok"] else f" — {r['message']}"
        lines.append(f"{mark} {r['type']} {r['name']} → {r['ip']}{detail}")
    return "\n".join(lines)


def _redact_webhooks(text, webhooks):
    """Strip webhook URLs (their path is a secret token) from error text."""
    for url in webhooks:
        text = text.replace(url, "<discord webhook>")
        # requests often embeds just the path portion (e.g. "url: /api/webhooks/…")
        path = url.split("discord.com", 1)[-1].split("discordapp.com", 1)[-1]
        if path.startswith("/") and len(path) > len("/api/webhooks/"):
            text = text.replace(path, "/api/webhooks/<redacted>")
    return text


def _channels_for(config, key):
    """Per-channel enable flags for one notification type, as
    {"discord": bool, "email": bool}. Tolerates the pre-migration single
    boolean shape in case config.json was hand-edited."""
    value = config.get(key, True)
    if isinstance(value, dict):
        return {"discord": bool(value.get("discord", True)),
                "email": bool(value.get("email", True))}
    return {"discord": bool(value), "email": bool(value)}


def _union_channels(*channel_dicts):
    """OR together per-channel flag dicts (None entries are skipped) — used
    when one combined message covers several notification types."""
    union = {"discord": False, "email": False}
    for channels in channel_dicts:
        if channels:
            union = {c: union[c] or channels.get(c, False) for c in union}
    return union


def _notify(config, message, subject="DDNS: public IP change detected",
            channels=None):
    """Send to every Discord webhook and all email recipients independently;
    return per-channel status. One channel failing never blocks the other.

    channels ({"discord": bool, "email": bool}, default both) lets each
    notification type silence a channel. A silenced or unconfigured channel
    is left out of the returned status, so the dashboard keeps showing the
    result of the last channel actually attempted."""
    if channels is None:
        channels = {"discord": True, "email": True}
    status = {}
    plain = message.replace("**", "")

    webhooks = config.get("discord_webhook_urls") or []
    if webhooks and channels.get("discord"):
        sent = 0
        last_error = None
        webhook_urls = [w["url"] for w in webhooks]
        for w in webhooks:
            try:
                send_discord_notification(w["url"], message, w.get("ping_user_ids"))
                sent += 1
            except requests.RequestException as exc:
                # requests error text includes the webhook URL, whose path IS
                # the secret token — redact before logging or displaying.
                last_error = _redact_webhooks(str(exc), webhook_urls)
                log.error("Discord notification failed: %s", last_error)
        if sent == len(webhooks):
            status["discord"] = "sent" if sent == 1 else f"sent to {sent} webhooks"
        else:
            status["discord"] = f"failed ({sent}/{len(webhooks)} sent): {last_error}"

    smtp_cfg = config.get("smtp", {})
    to_addrs = smtp_cfg.get("to_addrs") or []
    if smtp_cfg.get("host") and to_addrs and channels.get("email"):
        try:
            send_email_notification(smtp_cfg, subject, plain)
            status["email"] = "sent" if len(to_addrs) == 1 \
                else f"sent to {len(to_addrs)} recipients"
        except (smtplib.SMTPException, OSError) as exc:
            log.error("Email notification failed: %s", exc)
            status["email"] = f"failed: {exc}"

    return status


ALERT_DESCRIPTIONS = {
    "ip_lookup": "public IP lookup",
    "cloudflare": "Cloudflare API access",
}


def _set_alert(config, kind, message):
    """Raise a service-problem alert. Notifies only on the transition from
    healthy to failing, so a persistent outage alerts once, not every cycle."""
    state = config_store.get_state()
    already_active = state.get("alerts", {}).get(kind)
    config_store.update_state({"alerts": {kind: message}})
    channels = _channels_for(config, "notify_on_errors")
    if already_active or not any(channels.values()):
        return
    log.warning("Service problem (%s): %s", kind, message)
    notify_status = _notify(
        config,
        f"⚠️ **DDNS service problem** — {ALERT_DESCRIPTIONS[kind]} is failing.\n"
        f"{message}\n"
        f"The service keeps retrying every cycle; you'll get a recovery "
        f"notice when it clears.",
        subject="DDNS: service problem detected",
        channels=channels,
    )
    config_store.update_state({"notify": notify_status})


def _clear_alert(config, kind):
    """Clear an alert; notify on the transition back to healthy."""
    state = config_store.get_state()
    was_active = state.get("alerts", {}).get(kind)
    if not was_active:
        return
    config_store.update_state({"alerts": {kind: None}})
    channels = _channels_for(config, "notify_on_errors")
    if not any(channels.values()):
        return
    log.info("Service problem resolved (%s)", kind)
    notify_status = _notify(
        config,
        f"✅ **DDNS service recovered** — {ALERT_DESCRIPTIONS[kind]} is working again.",
        subject="DDNS: service recovered",
        channels=channels,
    )
    config_store.update_state({"notify": notify_status})


def _update_tracked_records(config, tracked, ipv4, ipv6):
    """PATCH each tracked record to the current IP. Returns per-record results
    and updates per-record state as it goes."""
    results = []
    token, zone = config["cloudflare_api_token"], config["cloudflare_zone_id"]
    now = time.time()

    for record in tracked:
        target_ip = ipv4 if record["type"] == "A" else ipv6
        rid, name, rtype = record["id"], record["name"], record["type"]
        if not target_ip:
            results.append({"id": rid, "name": name, "type": rtype, "ip": "n/a",
                            "ok": False,
                            "message": f"no public IPv{4 if rtype == 'A' else 6} address detected"})
            continue
        if record.get("content") == target_ip:
            config_store.update_state({"records": {rid: {
                "name": name, "type": rtype, "status": "ok",
                "message": "already up to date", "ts": now}}})
            continue
        try:
            cf.patch_dns_record_content(token, zone, rid, target_ip)
            results.append({"id": rid, "name": name, "type": rtype,
                            "ip": target_ip, "ok": True, "message": "updated"})
            config_store.update_state({"records": {rid: {
                "name": name, "type": rtype, "status": "ok",
                "message": f"updated to {target_ip}", "ts": now}}})
        except cf.CloudflareError as exc:
            log.error("Failed to update %s %s: %s", rtype, name, exc.message)
            results.append({"id": rid, "name": name, "type": rtype,
                            "ip": target_ip, "ok": False, "message": exc.message})
            config_store.update_state({"records": {rid: {
                "name": name, "type": rtype, "status": "error",
                "message": exc.message, "ts": now}}})
            if exc.is_auth_error:
                raise
    return results


def run_check_cycle(force_reconcile=False):
    """One full check/update/notify cycle. Never raises."""
    global _needs_reconcile
    config = config_store.get_config()
    state = config_store.get_state()
    now = time.time()

    ipv4, ipv6 = get_public_ips()
    if not ipv4 and not ipv6:
        config_store.update_state({"last_check_ts": now})
        _set_alert(config, "ip_lookup",
                   "Could not determine the public IP address from any lookup "
                   "service — the internet connection may be down.")
        return
    _clear_alert(config, "ip_lookup")
    ip_history.record_check(ipv4, ipv6, now)

    old_ipv4, old_ipv6 = state.get("last_ipv4"), state.get("last_ipv6")
    ip_changed = (ipv4 and ipv4 != old_ipv4) or (ipv6 and ipv6 != old_ipv6)
    reconcile = force_reconcile or _needs_reconcile

    if not ip_changed and not reconcile:
        config_store.update_state({
            "last_check_ts": now, "last_ipv4": ipv4 or old_ipv4,
            "last_ipv6": ipv6 or old_ipv6,
        })
        return

    tracked_ids = set(config.get("ddns_tracked_record_ids", []))
    if not tracked_ids or not config.get("cloudflare_api_token") \
            or not config.get("cloudflare_zone_id"):
        # Notify-only mode: no Cloudflare records to update, but IP changes
        # are still announced. A first-ever sighting (no stored previous IP)
        # sets the baseline silently rather than alerting "unknown → X".
        v4_changed = bool(old_ipv4 and ipv4 and ipv4 != old_ipv4)
        v6_changed = bool(old_ipv6 and ipv6 and ipv6 != old_ipv6)
        changed = v4_changed or v6_changed
        updates = {"last_check_ts": now, "last_ipv4": ipv4 or old_ipv4,
                   "last_ipv6": ipv6 or old_ipv6}
        if changed:
            updates["last_change_ts"] = now
        config_store.update_state(updates)
        # _needs_reconcile stays True on purpose: if Cloudflare gets
        # configured later, the next cycle then reconciles records right
        # away instead of waiting for the next IP change.
        if changed:
            log.info("IP change detected (v4: %s → %s, v6: %s → %s); "
                     "no Cloudflare records tracked — notifying only",
                     old_ipv4, ipv4, old_ipv6, ipv6)
            channels = _union_channels(
                _channels_for(config, "notify_ipv4_changes") if v4_changed else None,
                _channels_for(config, "notify_ipv6_changes") if v6_changed else None)
            if any(channels.values()):
                message = build_notification_message(
                    old_ipv4, ipv4, old_ipv6, ipv6, [])
                config_store.update_state(
                    {"notify": _notify(config, message, channels=channels)})
        return

    try:
        all_records = cf.list_dns_records(
            config["cloudflare_api_token"], config["cloudflare_zone_id"])
        config_store.update_state({"cloudflare_auth_ok": True,
                                   "cloudflare_error": None})
        _clear_alert(config, "cloudflare")
    except cf.CloudflareError as exc:
        log.error("Cloudflare list failed: %s", exc.message)
        _needs_reconcile = True
        config_store.update_state({
            "last_check_ts": now,
            "cloudflare_auth_ok": not exc.is_auth_error,
            "cloudflare_error": exc.message,
        })
        _set_alert(config, "cloudflare", exc.message)
        return

    tracked = [r for r in all_records
               if r["id"] in tracked_ids and r["type"] in ("A", "AAAA")]

    # Reconcile mode: only touch records whose content actually differs.
    needs_update = [r for r in tracked
                    if r.get("content") != (ipv4 if r["type"] == "A" else ipv6)]

    if not needs_update:
        _needs_reconcile = False
        config_store.update_state({
            "last_check_ts": now, "last_ipv4": ipv4, "last_ipv6": ipv6,
            "last_change_ts": state.get("last_change_ts"),
        })
        return

    log.info("IP change detected (v4: %s → %s, v6: %s → %s); updating %d record(s)",
             old_ipv4, ipv4, old_ipv6, ipv6, len(needs_update))

    try:
        results = _update_tracked_records(config, needs_update, ipv4, ipv6)
        _needs_reconcile = False
    except cf.CloudflareError as exc:
        _needs_reconcile = True
        config_store.update_state({
            "cloudflare_auth_ok": False, "cloudflare_error": exc.message,
        })
        _set_alert(config, "cloudflare", exc.message)
        results = [{"id": "-", "name": "(remaining records skipped)",
                    "type": "", "ip": "", "ok": False, "message": exc.message}]

    config_store.update_state({
        "last_check_ts": now, "last_ipv4": ipv4, "last_ipv6": ipv6,
        "last_change_ts": now,
    })

    # Per-family notification gate: an update touching only A records is an
    # IPv4 event, only AAAA an IPv6 event. Entries without a record type
    # (e.g. "remaining records skipped" after a Cloudflare failure) always
    # notify on every channel. If both families are involved, one combined
    # message goes to the union of their enabled channels.
    family_channels = {"A": _channels_for(config, "notify_ipv4_changes"),
                       "AAAA": _channels_for(config, "notify_ipv6_changes")}
    all_channels = {"discord": True, "email": True}
    channels = _union_channels(
        *(family_channels.get(r["type"], all_channels) for r in results))
    if results and any(channels.values()):
        message = build_notification_message(old_ipv4, ipv4, old_ipv6, ipv6, results)
        notify_status = _notify(config, message, channels=channels)
        config_store.update_state({"notify": notify_status})


def check_summary_due(config):
    """Send the scheduled summary notification when it is due, and keep the
    next-run time in state up to date (recomputed whenever the schedule
    settings change — the settings save wakes the poller, so a new schedule
    takes effect immediately).

    next_summary_ts persists in state.json, so a summary that came due while
    the service was down fires on the first cycle after startup — unless the
    user turned catch-up off, in which case it's skipped and the next
    scheduled summary covers the gap."""
    scfg = config.get("summary") or {}
    state = config_store.get_state()
    if not scfg.get("enabled"):
        if state.get("next_summary_ts"):
            config_store.update_state({"next_summary_ts": None,
                                       "summary_schedule": None})
        return

    now = time.time()
    fingerprint = summary.schedule_fingerprint(scfg)
    next_ts = state.get("next_summary_ts")
    if not next_ts or state.get("summary_schedule") != fingerprint:
        next_ts = summary.next_run_ts(scfg, now)
        config_store.update_state({"next_summary_ts": next_ts,
                                   "summary_schedule": fingerprint})
        log.info("Summary notification scheduled (%s); next at %s",
                 summary.describe_schedule(scfg),
                 time.strftime("%Y-%m-%d %H:%M", time.localtime(next_ts)))
        return
    if now < next_ts:
        return

    if not scfg.get("catch_up", True) and next_ts < summary.SERVICE_STARTED_TS:
        # The summary came due while the service was off and catch-up is
        # disabled: skip it rather than sending late. Advancing slot by slot
        # from the missed occurrence keeps the original cadence (matters for
        # bi-weekly); last_summary_ts stays put so the next summary still
        # covers the skipped period.
        new_next = next_ts
        while new_next <= now:
            new_next = summary.next_run_ts(scfg, new_next, just_sent=True)
        log.info("Summary was due at %s while the service was down — skipped "
                 "(catch-up is off); next at %s",
                 time.strftime("%Y-%m-%d %H:%M", time.localtime(next_ts)),
                 time.strftime("%Y-%m-%d %H:%M", time.localtime(new_next)))
        config_store.update_state({"next_summary_ts": new_next,
                                   "summary_schedule": fingerprint})
        return

    # Cover everything since the last summary; the very first one covers one
    # full period back.
    since = state.get("last_summary_ts") or (now - summary.period_seconds(scfg))
    new_next = summary.next_run_ts(scfg, now, just_sent=True)
    channels = {"discord": bool(scfg.get("discord", True)),
                "email": bool(scfg.get("email", True))}
    log.info("Sending %s summary (covering since %s)",
             summary.frequency_label(scfg),
             time.strftime("%Y-%m-%d %H:%M", time.localtime(since)))
    if any(channels.values()):
        message = summary.build_message(config, state, since, now,
                                        next_ts=new_next)
        notify_status = _notify(
            config, message,
            subject=f"DDNS: {summary.frequency_label(scfg)} summary",
            channels=channels)
        config_store.update_state({"notify": notify_status})
    config_store.update_state({"last_summary_ts": now,
                               "next_summary_ts": new_next,
                               "summary_schedule": fingerprint})


def poller_loop():
    """Main loop for the poller thread. First cycle is always a full
    reconcile against Cloudflare (the IP may have changed while the service
    was down)."""
    log.info("Poller started")
    first = True
    while not stop_event.is_set():
        try:
            run_check_cycle(force_reconcile=first)
        except Exception:
            log.exception("Unexpected error in poll cycle")
        first = False

        config = config_store.get_config()
        try:
            check_summary_due(config)
        except Exception:
            log.exception("Unexpected error in summary check")

        timeout = max(15, int(config.get("poll_interval_seconds", 300)))
        if (config.get("summary") or {}).get("enabled"):
            next_ts = config_store.get_state().get("next_summary_ts")
            if next_ts:
                # Cap the sleep so the summary goes out at its scheduled
                # time, not up to a poll interval late.
                timeout = min(timeout, max(5, next_ts - time.time() + 1))
        wake_event.wait(timeout=timeout)
        wake_event.clear()
    log.info("Poller stopped")
