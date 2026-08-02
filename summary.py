"""Scheduled summary notifications.

Pure scheduling math and message building for the periodic summary — the
recap of the period's IP changes that doubles as a proof-of-life signal.
The poller thread owns the actual timing and sending (see poller.py); web.py
uses display_next_ts() to show the next scheduled send on the Settings page.

All times are local server time, matching how every other timestamp in the
app is displayed. Config values arrive validated from the settings form, but
config.json is hand-editable, so everything here falls back to sane defaults
instead of raising.
"""

import datetime
import time

import ip_history

# Import time == process start; used for the proof-of-life uptime line.
SERVICE_STARTED_TS = time.time()

FREQUENCIES = ("daily", "weekly", "biweekly", "monthly")
FREQUENCY_LABELS = {"daily": "daily", "weekly": "weekly",
                    "biweekly": "bi-weekly", "monthly": "monthly"}
DAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
             "Saturday", "Sunday")

# Fallback lookback window for the very first summary, when there is no
# previous send to measure from.
_PERIOD_SECONDS = {"daily": 86400, "weekly": 7 * 86400,
                   "biweekly": 14 * 86400, "monthly": 31 * 86400}


def _frequency(scfg):
    freq = scfg.get("frequency", "weekly")
    return freq if freq in FREQUENCIES else "weekly"


def _parse_time(value):
    """'HH:MM' -> (hour, minute), defaulting to 01:00 on any bad value."""
    try:
        hh, mm = str(value).split(":")
        hh, mm = int(hh), int(mm)
        if 0 <= hh <= 23 and 0 <= mm <= 59:
            return hh, mm
    except (ValueError, AttributeError):
        pass
    return 1, 0


def _day_of_week(scfg):
    try:
        return int(scfg.get("day_of_week", 6)) % 7
    except (TypeError, ValueError):
        return 6


def _day_of_month(scfg):
    try:
        return min(max(int(scfg.get("day_of_month", 1)), 1), 28)
    except (TypeError, ValueError):
        return 1


def frequency_label(scfg):
    return FREQUENCY_LABELS[_frequency(scfg)]


def period_seconds(scfg):
    return _PERIOD_SECONDS[_frequency(scfg)]


def schedule_fingerprint(scfg):
    """Compact string of every setting that affects the schedule. Stored in
    state next to next_summary_ts so the poller can tell when a settings
    change invalidates the computed next-run time."""
    return "|".join([_frequency(scfg), str(_day_of_week(scfg)),
                     str(_day_of_month(scfg)),
                     "%02d:%02d" % _parse_time(scfg.get("time"))])


def describe_schedule(scfg):
    """Human-readable schedule, e.g. 'every other Sunday at 01:00'."""
    freq = _frequency(scfg)
    at = "%02d:%02d" % _parse_time(scfg.get("time"))
    if freq == "daily":
        return f"every day at {at}"
    if freq == "weekly":
        return f"every {DAY_NAMES[_day_of_week(scfg)]} at {at}"
    if freq == "biweekly":
        return f"every other {DAY_NAMES[_day_of_week(scfg)]} at {at}"
    return f"monthly on day {_day_of_month(scfg)} at {at}"


def next_run_ts(scfg, after_ts, just_sent=False):
    """Epoch of the first scheduled occurrence strictly after after_ts.

    just_sent=True means a summary was just sent at after_ts; for the
    bi-weekly frequency that skips the very next weekly slot so sends land
    ~14 days apart. (When first enabled, the first send is simply the next
    upcoming slot.)
    """
    freq = _frequency(scfg)
    hh, mm = _parse_time(scfg.get("time"))
    after = datetime.datetime.fromtimestamp(after_ts)
    if freq == "biweekly" and just_sent:
        after += datetime.timedelta(days=7)

    if freq == "daily":
        cand = after.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if cand <= after:
            cand += datetime.timedelta(days=1)
    elif freq in ("weekly", "biweekly"):
        cand = after.replace(hour=hh, minute=mm, second=0, microsecond=0)
        cand += datetime.timedelta(days=(_day_of_week(scfg) - cand.weekday()) % 7)
        if cand <= after:
            cand += datetime.timedelta(days=7)
    else:  # monthly — day_of_month is clamped to 1–28, valid in every month
        cand = after.replace(day=_day_of_month(scfg), hour=hh, minute=mm,
                             second=0, microsecond=0)
        if cand <= after:
            if cand.month == 12:
                cand = cand.replace(year=cand.year + 1, month=1)
            else:
                cand = cand.replace(month=cand.month + 1)
    return cand.timestamp()


def matches_schedule(scfg, ts):
    """True if ts still falls on the configured wall-clock slot in the
    current local timezone.

    next_run_ts() bakes the server's UTC offset into the epoch it returns,
    but the schedule fingerprint only captures the wall-clock settings — so
    a stored next-run time survives a timezone change (or a DST transition
    between now and the slot) even though it no longer lands at the
    configured local time. Callers use this to detect that drift and
    recompute."""
    hh, mm = _parse_time(scfg.get("time"))
    cand = datetime.datetime.fromtimestamp(ts)
    if (cand.hour, cand.minute) != (hh, mm):
        return False
    freq = _frequency(scfg)
    if freq in ("weekly", "biweekly"):
        return cand.weekday() == _day_of_week(scfg)
    if freq == "monthly":
        return cand.day == _day_of_month(scfg)
    return True


def display_next_ts(scfg, state):
    """Next scheduled send for display (Settings page), or None if the
    summary is disabled. Prefers the poller's stored value; falls back to a
    fresh computation when the stored one is stale (schedule just changed and
    the poller hasn't caught up) or missing."""
    if not scfg.get("enabled"):
        return None
    next_ts = state.get("next_summary_ts")
    if next_ts and next_ts > time.time() \
            and state.get("summary_schedule") == schedule_fingerprint(scfg) \
            and matches_schedule(scfg, next_ts):
        return next_ts
    return next_run_ts(scfg, time.time())


# --- message building --------------------------------------------------------

def _fmt(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _fmt_duration(seconds):
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if not parts or minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    return ", ".join(parts[:2])


def _change_lines(rows, since_ts):
    """One line per address change inside the period. Rows also include each
    family's range that was already active at since_ts, purely so the first
    in-period change can name the address it replaced."""
    lines = []
    prev_by_family = {}
    for row in sorted(rows, key=lambda r: (r["family"], r["started_ts"])):
        prev = prev_by_family.get(row["family"])
        prev_by_family[row["family"]] = row
        if row["started_ts"] < since_ts:
            continue
        old = prev["ip"] if prev else "unknown"
        lines.append(f"• {row['family']}: {old} → {row['ip']}"
                     f" ({_fmt(row['started_ts'])})")
    return lines


def build_message(config, state, since_ts, now_ts, next_ts=None):
    """The summary text shared by both channels (Discord markdown; the email
    path strips the ** markers, same as every other notification)."""
    scfg = config.get("summary", {})
    lines = [f"📋 **DDNS Manager {frequency_label(scfg)} summary** — "
             f"the service is up and running.",
             f"Covering {_fmt(since_ts)} → {_fmt(now_ts)}.", ""]

    try:
        rows = ip_history.get_ranges_since(since_ts)
    except Exception:  # advisory, like all history: never break the send
        rows = None
    if rows is None:
        lines.append("IP history is unavailable (database error) — "
                     "see the service log.")
    else:
        changes = _change_lines(rows, since_ts)
        if changes:
            lines.append(f"**IP address changes this period: {len(changes)}**")
            lines.extend(changes)
        else:
            lines.append("No IP address changes this period.")

    lines.append("")
    lines.append("**Status**")
    lines.append(f"IPv4: {state.get('last_ipv4') or 'not detected'}")
    lines.append(f"IPv6: {state.get('last_ipv6') or 'not detected'}")
    if config.get("cloudflare_api_token") and config.get("cloudflare_zone_id"):
        tracked = len(config.get("ddns_tracked_record_ids", []))
        lines.append(f"DNS records kept updated: {tracked}")
    else:
        lines.append("Mode: notification-only (no Cloudflare records managed)")
    if state.get("last_check_ts"):
        lines.append(f"Last IP check: {_fmt(state['last_check_ts'])}")
    lines.append(f"Service uptime: {_fmt_duration(now_ts - SERVICE_STARTED_TS)}")
    for kind, message in (state.get("alerts") or {}).items():
        if message:
            lines.append(f"⚠️ Active problem ({kind}): {message}")
    if next_ts:
        lines.append(f"Next summary: {_fmt(next_ts)}")
    return "\n".join(lines)
