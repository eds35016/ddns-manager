"""Tests for the IP history SQLite backend."""

import importlib
import os
import sqlite3

import pytest


class TestIpHistory:
    """Tests for ip_history module."""

    def _make_ip_history(self, temp_dir):
        """Import/reload ip_history with a fresh DB path."""
        db_path = os.path.join(temp_dir, "history.db")
        os.environ["DDNS_HISTORY_DB"] = db_path
        import ip_history as m
        m._initialized = False
        importlib.reload(m)
        return db_path, m

    def test_record_check_creates_entry(self, temp_dir):
        """First record_check with an IP should insert a row."""
        _, ip_history = self._make_ip_history(temp_dir)
        ip_history.record_check("1.2.3.4", "2001:db8::1", 1000.0)
        rows = ip_history.get_all()
        assert len(rows) == 2
        families = {r["family"] for r in rows}
        assert families == {"IPv4", "IPv6"}

    def test_record_check_no_duplicate(self, temp_dir):
        """Calling record_check with the same IP should not add a row."""
        _, ip_history = self._make_ip_history(temp_dir)
        ip_history.record_check("1.2.3.4", None, 1000.0)
        ip_history.record_check("1.2.3.4", None, 1010.0)
        rows = ip_history.get_all()
        ipv4_rows = [r for r in rows if r["family"] == "IPv4"]
        assert len(ipv4_rows) == 1
        assert ipv4_rows[0]["ended_ts"] is None

    def test_record_check_on_change_closes_previous(self, temp_dir):
        """On IP change, the old range should be closed."""
        _, ip_history = self._make_ip_history(temp_dir)
        ip_history.record_check("1.2.3.4", None, 1000.0)
        ip_history.record_check("5.6.7.8", None, 2000.0)
        rows = ip_history.get_all()
        ipv4_rows = sorted(rows, key=lambda r: r["started_ts"])
        assert len(ipv4_rows) == 2
        assert ipv4_rows[0]["ip"] == "1.2.3.4"
        assert ipv4_rows[0]["ended_ts"] == 2000.0
        assert ipv4_rows[1]["ip"] == "5.6.7.8"
        assert ipv4_rows[1]["ended_ts"] is None

    def test_get_page_pagination(self, temp_dir):
        """get_page should support keyset pagination."""
        _, ip_history = self._make_ip_history(temp_dir)
        now = 1000.0
        for i in range(25):
            ip_history.record_check(f"10.0.0.{i}", None, now + i * 60)

        page1, has_more = ip_history.get_page(limit=10)
        assert len(page1) <= 10
        last_id = page1[-1]["id"]
        page2, has_more = ip_history.get_page(before_id=last_id, limit=10)
        assert len(page2) > 0
        assert all(r["id"] < last_id for r in page2)

    def test_get_page_family_filter(self, temp_dir):
        """Family filter should only return rows for that family."""
        _, ip_history = self._make_ip_history(temp_dir)
        ip_history.record_check("1.2.3.4", "2001:db8::1", 1000.0)
        v4_rows, _ = ip_history.get_page(family="IPv4")
        v6_rows, _ = ip_history.get_page(family="IPv6")
        assert len(v4_rows) == 1
        assert v4_rows[0]["family"] == "IPv4"
        assert len(v6_rows) == 1
        assert v6_rows[0]["family"] == "IPv6"

    def test_get_ranges_since(self, temp_dir):
        _, ip_history = self._make_ip_history(temp_dir)
        ip_history.record_check("1.2.3.4", None, 1000.0)
        ip_history.record_check("5.6.7.8", None, 2000.0)
        ranges = ip_history.get_ranges_since(1500.0)
        assert any(r["started_ts"] == 2000.0 for r in ranges)

    def test_get_all_ordering(self, temp_dir):
        """get_all should return newest first."""
        _, ip_history = self._make_ip_history(temp_dir)
        ip_history.record_check("1.2.3.4", None, 1000.0)
        ip_history.record_check("5.6.7.8", None, 2000.0)
        all_rows = ip_history.get_all()
        assert all_rows[0]["started_ts"] >= all_rows[-1]["started_ts"]

    def test_none_ip_skipped(self, temp_dir):
        """A None address should not create a history entry."""
        _, ip_history = self._make_ip_history(temp_dir)
        ip_history.record_check(None, None, 1000.0)
        rows = ip_history.get_all()
        assert len(rows) == 0

    def test_invalid_db_does_not_raise(self, temp_dir):
        """A database error should be logged, not raised."""
        db_path, ip_history = self._make_ip_history(temp_dir)
        # First make a valid call so the DB gets created
        ip_history.record_check("1.2.3.4", None, 1000.0)
        # Replace the DB file with a directory to cause a write error
        os.remove(db_path)
        os.mkdir(db_path)
        # This should not raise (errors logged, not raised)
        ip_history.record_check("5.6.7.8", None, 2000.0)
        # querying should also work (previous data in memory) then fail
        with pytest.raises(sqlite3.Error):
            ip_history.get_all()
