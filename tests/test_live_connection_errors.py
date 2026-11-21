"""Regression tests for safe Wazuh HTTPS error handling.

These tests never connect to Wazuh or the internet.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workbench.live import LiveSourceError, _check_local_url, fetch_recent_alerts


class LiveConnectionErrorTests(unittest.TestCase):
    URL = "https://127.0.0.1:9200"

    def _raises(self, exception, text):
        requester = Mock(side_effect=exception)
        with self.assertRaisesRegex(LiveSourceError, text) as result:
            fetch_recent_alerts(self.URL, "readonly", "fake-password", requester=requester)
        # Important: never display a raw exception, which may contain private input.
        self.assertNotIn("fake-password", str(result.exception))

    def test_tunnel_refused_is_not_reported_as_ca_error(self):
        self._raises(requests.exceptions.ConnectionError("connection refused"), "SSH tunnel")

    def test_timeout_is_not_reported_as_ca_error(self):
        self._raises(requests.exceptions.ReadTimeout("simulated timeout"), "SSH tunnel")

    def test_tls_validation_has_distinct_message(self):
        self._raises(requests.exceptions.SSLError("bad certificate"), "TLS verification")

    def test_other_http_client_error_has_distinct_message(self):
        self._raises(requests.exceptions.RequestException("test only"), "HTTPS request failed")

    def test_local_os_error_is_distinguished(self):
        self._raises(OSError("test only"), "local file or SSL initialization")

    def test_invalid_urls_do_not_crash_or_leak_credentials(self):
        for url in ["https://127.0.0.1:notaport", "https://evil.test:9200",
                    "http://127.0.0.1:9200", "https://127.0.0.1:9200/other",
                    "https://name:secret@127.0.0.1:9200", "https://127.0.0.1:9200?x=y"]:
            with self.subTest(url=url):
                with self.assertRaisesRegex(LiveSourceError, "SSH port forward"):
                    _check_local_url(url)

    def test_missing_ca_reported_before_request(self):
        requester = Mock()
        with tempfile.TemporaryDirectory() as folder:
            with patch("workbench.live.PROJECT_ROOT", Path(folder)):
                with self.assertRaisesRegex(LiveSourceError, "CA certificate"):
                    fetch_recent_alerts(self.URL, "readonly", "fake-password",
                                        ca_bundle=".streamlit/certs/missing.pem", requester=requester)
        requester.assert_not_called()

    def test_valid_response_normalized_and_tls_verified(self):
        result = Mock(status_code=200)
        result.json.return_value = {"hits": {"hits": [
            {"_id": "123", "_index": "wazuh-alerts-x", "_source": {
                "timestamp": "2026-11-20T13:00:00Z", "rule": {"id": "100121", "level": 7,
                "description": "DO NOT LEAK SECRET"}, "agent": {"id": "001"}}}
        ]}}
        requester = Mock(return_value=result)
        events = fetch_recent_alerts(self.URL, "readonly", "fake-password", requester=requester)
        self.assertEqual(len(events), 1)
        self.assertNotIn("SECRET", str(events))
        self.assertTrue(requester.call_args.kwargs["verify"])
        self.assertEqual(requester.call_args.kwargs["allow_redirects"], False)


if __name__ == "__main__":
    unittest.main()
