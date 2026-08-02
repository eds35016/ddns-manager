"""Shared fixtures for DDNS Manager tests."""

import copy
import os
import tempfile
from unittest.mock import Mock, patch

import pytest


@pytest.fixture
def sample_config():
    """Return a realistic config dict (deep-copied per test)."""
    return {
        "admin_username": "admin",
        "admin_password_hash": "scrypt:...",
        "session_secret": "test-secret-32-chars-minimum!!",
        "bind_host": "0.0.0.0",
        "bind_port": 8080,
        "poll_interval_seconds": 300,
        "cloudflare_api_token": "",
        "cloudflare_zone_id": "",
        "ddns_tracked_record_ids": [],
        "discord_webhook_urls": [],
        "smtp": {
            "host": "",
            "port": 587,
            "security": "starttls",
            "username": "",
            "password": "",
            "from_addr": "",
            "to_addrs": [],
        },
        "notify_ipv4_changes": {"discord": True, "email": True},
        "notify_ipv6_changes": {"discord": True, "email": True},
        "notify_on_errors": {"discord": True, "email": True},
        "summary": {
            "enabled": False,
            "frequency": "weekly",
            "day_of_week": 6,
            "day_of_month": 1,
            "time": "01:00",
            "catch_up": True,
            "discord": True,
            "email": True,
        },
    }


@pytest.fixture
def sample_state():
    """Return a realistic state dict (deep-copied per test)."""
    return {
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


@pytest.fixture
def sample_tracked_records():
    """Sample Cloudflare DNS record dicts as returned by list_dns_records."""
    return [
        {
            "id": "a1b2c3d4e5f6a7b8c9d0e1f2",
            "type": "A",
            "name": "home.example.com",
            "content": "1.2.3.4",
            "proxied": True,
            "ttl": 1,
        },
        {
            "id": "b2c3d4e5f6a7b8c9d0e1f2a3",
            "type": "AAAA",
            "name": "home.example.com",
            "content": "2001:db8::1",
            "proxied": False,
            "ttl": 1,
        },
    ]


@pytest.fixture
def temp_dir():
    """Yield a temporary directory, cleaned up after the test."""
    with tempfile.TemporaryDirectory() as td:
        old_cwd = os.getcwd()
        os.chdir(td)
        yield td
        os.chdir(old_cwd)


@pytest.fixture
def mock_requests_get():
    """Mock requests.get for IP lookup tests."""
    with patch("requests.get") as mock:
        yield mock


@pytest.fixture
def mock_requests_post():
    """Mock requests.post for webhook tests."""
    with patch("requests.post") as mock:
        yield mock
