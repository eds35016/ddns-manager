"""Tests for config/state persistence."""

import json
import os
import pytest


@pytest.fixture(autouse=True)
def clear_globals():
    """Reset module-level state between tests."""
    import config_store
    with config_store._lock:
        config_store._config = None
    with config_store._state_lock:
        config_store._state = {
            "last_ipv4": None,
            "last_ipv6": None,
            "last_check_ts": None,
            "last_change_ts": None,
            "cloudflare_auth_ok": True,
            "cloudflare_error": None,
            "records": {},
            "notify": {"discord": None, "email": None},
            "alerts": {},
            "last_summary_ts": None,
            "next_summary_ts": None,
            "summary_schedule": None,
        }
    yield


def _import_with_paths(config_path, state_path):
    """Import config_store with env vars set so module-level paths resolve."""
    import importlib
    import config_store as cs
    # Force re-evaluation of module-level CONSTANTS by reloading
    os.environ["DDNS_CONFIG"] = config_path
    os.environ["DDNS_STATE"] = state_path
    importlib.reload(cs)
    return cs


def test_load_config_creates_defaults(temp_dir):
    """Fresh start: load_config should create config.json with generated creds."""
    config_path = os.path.join(temp_dir, "config.json")
    state_path = os.path.join(temp_dir, "state.json")
    config_store = _import_with_paths(config_path, state_path)

    cfg, password = config_store.load_config()
    assert password is not None
    assert len(password) >= 10
    assert cfg["admin_username"] == "admin"
    assert cfg["bind_host"] == "0.0.0.0"
    assert cfg["bind_port"] == 8080
    assert cfg["poll_interval_seconds"] == 300
    assert cfg["admin_password_hash"] != ""
    assert cfg["session_secret"] != ""
    assert os.path.exists(config_path)
    mode = os.stat(config_path).st_mode & 0o777
    assert mode == 0o600, f"Expected 0600, got {oct(mode)}"


def test_load_config_persists_across_runs(temp_dir):
    """Second load should return same config (no new password)."""
    config_path = os.path.join(temp_dir, "config.json")
    state_path = os.path.join(temp_dir, "state.json")
    config_store = _import_with_paths(config_path, state_path)

    cfg1, password1 = config_store.load_config()
    cfg2, password2 = config_store.load_config()
    assert password2 is None
    assert cfg2["admin_password_hash"] == cfg1["admin_password_hash"]
    assert cfg2["session_secret"] == cfg1["session_secret"]


def test_update_config(temp_dir):
    """update_config should merge changes and persist atomically."""
    config_path = os.path.join(temp_dir, "config.json")
    state_path = os.path.join(temp_dir, "state.json")
    config_store = _import_with_paths(config_path, state_path)

    config_store.load_config()
    config_store.update_config({"bind_port": 9090, "poll_interval_seconds": 600})
    cfg = config_store.get_config()
    assert cfg["bind_port"] == 9090
    assert cfg["poll_interval_seconds"] == 600
    with open(config_path) as f:
        saved = json.load(f)
    assert saved["bind_port"] == 9090
    assert saved["poll_interval_seconds"] == 600


def test_update_config_preserves_nested(temp_dir):
    """Updating one SMTP field shouldn't wipe others."""
    config_path = os.path.join(temp_dir, "config.json")
    state_path = os.path.join(temp_dir, "state.json")
    config_store = _import_with_paths(config_path, state_path)

    config_store.load_config()
    config_store.update_config({"smtp": {"host": "mail.example.com"}})
    cfg = config_store.get_config()
    assert cfg["smtp"]["host"] == "mail.example.com"
    assert cfg["smtp"]["port"] == 587
    assert cfg["smtp"]["security"] == "starttls"


def test_state_persistence(temp_dir):
    """State should persist and reload correctly."""
    config_path = os.path.join(temp_dir, "config.json")
    state_path = os.path.join(temp_dir, "state.json")
    config_store = _import_with_paths(config_path, state_path)

    config_store.load_state()
    config_store.update_state({"last_ipv4": "1.2.3.4", "last_check_ts": 1000.0})
    state = config_store.get_state()
    assert state["last_ipv4"] == "1.2.3.4"
    assert state["last_check_ts"] == 1000.0
    config_store.load_state()
    state2 = config_store.get_state()
    assert state2["last_ipv4"] == "1.2.3.4"
    assert state2["last_check_ts"] == 1000.0
