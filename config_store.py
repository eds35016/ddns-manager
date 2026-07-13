"""Thread-safe configuration and state persistence.

Config (config.json) holds secrets and user settings — written only on user
action from the GUI, chmod 600 on the Pi. State (state.json) holds advisory
runtime status written every poll cycle. Both are written atomically
(tmp + os.replace) so a power loss on the Pi's SD card never leaves a
half-written JSON file.

The lock is held only long enough to copy the dict in or out — never across
network or disk-flush-heavy work — so a slow Cloudflare call in one thread
can't stall the web UI or the poller.
"""

import copy
import json
import logging
import os
import secrets
import stat
import string
import threading

from werkzeug.security import generate_password_hash

log = logging.getLogger(__name__)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("DDNS_CONFIG", os.path.join(_BASE_DIR, "config.json"))
STATE_PATH = os.environ.get("DDNS_STATE", os.path.join(_BASE_DIR, "state.json"))

DEFAULT_CONFIG = {
    "admin_username": "admin",
    "admin_password_hash": "",  # set on first run
    "session_secret": "",       # set on first run
    "bind_host": "0.0.0.0",
    "bind_port": 8080,
    "poll_interval_seconds": 300,
    "cloudflare_api_token": "",
    "cloudflare_zone_id": "",
    # DNS record IDs (Cloudflare-assigned) the poller keeps updated with the
    # current public IP. Only A/AAAA records belong here.
    "ddns_tracked_record_ids": [],
    "discord_webhook_urls": [],
    "smtp": {
        "host": "",
        "port": 587,
        "security": "starttls",  # starttls | ssl | none
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addrs": [],
    },
    # Which address-family changes trigger a notification. Disabling one
    # never stops DNS record updates — it only silences the alerts (useful
    # when an ISP rotates the IPv6 prefix constantly).
    "notify_ipv4_changes": True,
    "notify_ipv6_changes": True,
    # Also alert (once per incident, plus a recovery notice) when the service
    # itself has a problem: IP lookup failing, Cloudflare unreachable, etc.
    "notify_on_errors": True,
}

# Keys whose values must never be echoed back to the browser or logs.
SECRET_KEYS = {"cloudflare_api_token", "discord_webhook_urls", "session_secret",
               "admin_password_hash"}

_lock = threading.Lock()
_config = None

_state_lock = threading.Lock()
_state = {
    "last_ipv4": None,
    "last_ipv6": None,
    "last_check_ts": None,
    "last_change_ts": None,
    "cloudflare_auth_ok": True,
    "cloudflare_error": None,
    "records": {},  # record_id -> {name, type, status, message, ts}
    "notify": {"discord": None, "email": None},
    # Active service problems, kind -> message ("ip_lookup", "cloudflare").
    # Used to alert once on failure and once on recovery, not every cycle.
    "alerts": {},
}


def _atomic_write(path, data, private=False):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    if private and os.name == "posix":
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp, path)


def _generate_password(length=20):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _merge_defaults(cfg, defaults):
    """Fill in any keys missing from an older config file."""
    for key, value in defaults.items():
        if key not in cfg:
            cfg[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(cfg[key], dict):
            _merge_defaults(cfg[key], value)
    return cfg


def _migrate_notify_flags(cfg):
    """Older configs had a single notifications_enabled switch for IP-change
    alerts; split it into per-family flags, preserving the user's choice.
    Must run before _merge_defaults, which would otherwise fill the new keys
    with True and lose a saved "off" setting."""
    old = cfg.pop("notifications_enabled", None)
    if old is not None:
        cfg.setdefault("notify_ipv4_changes", bool(old))
        cfg.setdefault("notify_ipv6_changes", bool(old))
    return cfg


def _migrate_webhooks(cfg):
    """Older configs stored discord_webhook_urls as a plain list of URL
    strings. Upgrade each entry to {"url", "ping_user_ids"} in place so the
    rest of the app only ever deals with one shape."""
    webhooks = cfg.get("discord_webhook_urls", [])
    cfg["discord_webhook_urls"] = [
        {"url": w, "ping_user_ids": []} if isinstance(w, str) else w
        for w in webhooks
    ]
    return cfg


def load_config():
    """Load config.json, creating it with generated credentials on first run.

    Returns (config_copy, generated_password_or_None). The generated password
    is returned exactly once so the caller can print it for the user; it is
    never persisted in plaintext.
    """
    global _config
    generated_password = None
    with _lock:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                _config = _merge_defaults(
                    _migrate_notify_flags(json.load(f)), DEFAULT_CONFIG)
        else:
            _config = copy.deepcopy(DEFAULT_CONFIG)
        _migrate_webhooks(_config)

        changed = False
        if not _config["admin_password_hash"]:
            generated_password = _generate_password()
            _config["admin_password_hash"] = generate_password_hash(generated_password)
            changed = True
        if not _config["session_secret"]:
            _config["session_secret"] = secrets.token_hex(32)
            changed = True
        if changed or not os.path.exists(CONFIG_PATH):
            _atomic_write(CONFIG_PATH, _config, private=True)
        return copy.deepcopy(_config), generated_password


def get_config():
    """Return a snapshot copy of the current config."""
    with _lock:
        return copy.deepcopy(_config)


def update_config(changes):
    """Merge a dict of changes into the config and persist atomically.

    Nested dicts (e.g. smtp) are merged one level deep so a settings form
    that omits the password doesn't wipe it.
    """
    with _lock:
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(_config.get(key), dict):
                _config[key].update(value)
            else:
                _config[key] = value
        _atomic_write(CONFIG_PATH, _config, private=True)
        return copy.deepcopy(_config)


def load_state():
    global _state
    with _state_lock:
        if os.path.exists(STATE_PATH):
            try:
                with open(STATE_PATH, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                _state.update(saved)
            except (json.JSONDecodeError, OSError) as exc:
                log.warning("Could not read state file, starting fresh: %s", exc)
        return copy.deepcopy(_state)


def get_state():
    with _state_lock:
        return copy.deepcopy(_state)


def update_state(changes):
    with _state_lock:
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(_state.get(key), dict):
                _state[key].update(value)
            else:
                _state[key] = value
        try:
            _atomic_write(STATE_PATH, _state)
        except OSError as exc:
            # State is advisory (dashboard display); never let a disk hiccup
            # kill the poll cycle.
            log.warning("Could not persist state file: %s", exc)
        return copy.deepcopy(_state)
