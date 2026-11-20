"""Unit tests for live sync scheduling (no Wazuh server needed)."""
import unittest
from datetime import datetime, timedelta, timezone
from workbench.refresh import should_fetch_live


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)
        self.params = dict(key=('same',), saved_key=('same',), now=self.now)

    def test_manual_sync_forces_refresh(self):
        self.assertTrue(should_fetch_live(force=True, auto_refresh=False,
                        last_attempt=self.now, **self.params))

    def test_no_fetch_when_auto_off(self):
        self.assertFalse(should_fetch_live(force=False, auto_refresh=False,
                         last_attempt=self.now - timedelta(minutes=5), **self.params))

    def test_auto_sync_waits_until_due(self):
        for seconds, expected in [(30, False), (59, False), (60, True), (70, True)]:
            with self.subTest(seconds=seconds):
                self.assertEqual(should_fetch_live(force=False, auto_refresh=True,
                    last_attempt=self.now - timedelta(seconds=seconds), **self.params), expected)

    def test_new_credentials_or_time_window_refresh_immediately(self):
        self.assertTrue(should_fetch_live(force=False, auto_refresh=False,
            last_attempt=self.now, key=('different',), saved_key=('same',), now=self.now))

    def test_initial_fetch(self):
        self.assertTrue(should_fetch_live(force=False, auto_refresh=True,
                        last_attempt=None, **self.params))


if __name__ == '__main__':
    unittest.main()
