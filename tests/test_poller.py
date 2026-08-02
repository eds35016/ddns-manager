"""Tests for the poller module - notification building and IP lookup."""

import pytest
from unittest.mock import Mock, patch

import poller


class TestPoller:
    """Tests for poller.py notification and IP utilities."""

    def test_build_notification_message_change(self):
        """A basic IP change should produce a readable message."""
        results = [
            {"id": "r1", "name": "home.example.com", "type": "A",
             "ip": "1.2.3.5", "ok": True, "message": "updated"},
        ]
        msg = poller.build_notification_message(
            "1.2.3.4", "1.2.3.5", None, None, results)
        assert "Public IP address change detected" in msg
        assert "1.2.3.4" in msg
        assert "1.2.3.5" in msg
        assert "1 succeeded" in msg
        assert "✅" in msg

    def test_build_notification_message_failure(self):
        """A failed DNS update should be reported as failure."""
        results = [
            {"id": "r1", "name": "home.example.com", "type": "A",
             "ip": "1.2.3.5", "ok": False, "message": "Token expired"},
        ]
        msg = poller.build_notification_message(
            "1.2.3.4", "1.2.3.5", None, None, results)
        assert "0 succeeded, 1 failed" in msg
        assert "❌" in msg
        assert "Token expired" in msg

    def test_build_notification_notify_only(self):
        """With empty results, should note notification-only mode."""
        msg = poller.build_notification_message(
            None, "1.2.3.4", None, None, [])
        assert "notification-only mode" in msg

    def test_build_notification_ipv6_change(self):
        """IPv6 changes should be reported too."""
        results = []
        msg = poller.build_notification_message(
            "1.2.3.4", "1.2.3.5",
            "2001:db8::1", "2001:db8::2",
            [])
        assert "IPv4" in msg
        assert "IPv6" in msg

    def test_redact_webhooks(self):
        """Webhook URLs should be stripped from error messages."""
        urls = ["https://discord.com/api/webhooks/abc123/token-secret"]
        text = "Error at https://discord.com/api/webhooks/abc123/token-secret"
        result = poller._redact_webhooks(text, urls)
        assert "token-secret" not in result
        assert "<discord webhook>" in result

    def test_union_channels(self):
        """OR of channel flags should work correctly."""
        a = {"discord": True, "email": False}
        b = {"discord": False, "email": True}
        result = poller._union_channels(a, b)
        assert result["discord"] is True
        assert result["email"] is True

    def test_union_channels_none_skipped(self):
        a = {"discord": True, "email": False}
        result = poller._union_channels(a, None)
        assert result["discord"] is True
        assert result["email"] is False

    @patch("requests.get")
    def test_fetch_ip_success(self, mock_get):
        """_fetch_ip should return the validated IP."""
        mock_get.return_value = Mock(
            status_code=200,
            text="1.2.3.4\n",
            json=lambda: {},
            raise_for_status=lambda: None,
        )
        result = poller._fetch_ip(
            ["https://api.ipify.org"],
            lambda a: a.version == 4)
        assert result == "1.2.3.4"

    @patch("requests.get")
    def test_fetch_ip_validation(self, mock_get):
        """HTML response should be rejected by ipaddress validation."""
        mock_get.return_value = Mock(
            status_code=200,
            text="<html>captive portal</html>\n",
            raise_for_status=lambda: None,
        )
        result = poller._fetch_ip(
            ["https://api.ipify.org"],
            lambda a: a.version == 4)
        assert result is None

    @patch("poller.send_discord_notification")
    @patch("poller.send_email_notification")
    def test_notify_discord_only(self, mock_email, mock_discord, sample_config):
        """_notify with only Discord configured should only call Discord."""
        config = dict(sample_config)
        config["discord_webhook_urls"] = [{"url": "https://discord.com/api/webhooks/abc", "ping_user_ids": []}]
        config["smtp"] = {"host": "", "port": 587, "security": "starttls",
                          "username": "", "password": "", "from_addr": "", "to_addrs": []}
        result = poller._notify(
            config, "Test message", channels={"discord": True, "email": False})
        assert mock_discord.called
        assert not mock_email.called
