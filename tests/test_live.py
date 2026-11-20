import unittest
from unittest.mock import Mock, patch
import tempfile
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from workbench.live import fetch_recent_alerts, sanitize_hit, LiveSourceError


class IndexerIntegrationTests(unittest.TestCase):
    def test_sanitizes_event_and_does_not_expose_sensitive_data(self):
        hit={'_source':{
            'timestamp':'2026-11-19T12:00:00+00:00',
            'rule':{'id':'100121', 'level':7, 'description':'User discovery', 'groups':['sysmon']},
            'agent':{'id':'001','name':'PERSONAL_HOSTNAME','ip':'192.168.1.100'},
            'data':{'win':{'eventdata':{'commandLine':'SECRET IN COMMAND LINE'}}},
        }}
        event=sanitize_hit(hit)
        self.assertEqual(event['agent'],'endpoint-001')
        self.assertNotIn('PERSONAL_HOSTNAME',str(event))
        self.assertNotIn('SECRET',str(event))

    def test_rejects_nonlocal_indexer(self):
        with self.assertRaises(LiveSourceError):
            fetch_recent_alerts('https://evil.example:9200','u','p')
        with self.assertRaises(LiveSourceError):
            fetch_recent_alerts('http://127.0.0.1:9200','u','p')

    def test_limited_authenticated_search_and_safe_projection(self):
        result={'hits':{'hits':[{'_source':{
            'timestamp':'2026-11-19T12:00:00+00:00',
            'rule':{'id':'60122','level':5,'description':'Logon failed','groups':['authentication_failed']},
            'agent':{'id':'001','name':'SENSITIVE'},
        }}]}}
        responder=Mock(status_code=200)
        responder.json.return_value=result
        requester=Mock(return_value=responder)
        alerts=fetch_recent_alerts('https://127.0.0.1:9200', 'readonly', 'secret',
                                   verify_tls=True, requester=requester)
        self.assertEqual(len(alerts),1)
        self.assertEqual(alerts[0]['agent'],'endpoint-001')
        arguments, kwargs=requester.call_args
        self.assertEqual(kwargs['auth'],('readonly','secret'))
        self.assertTrue(kwargs['verify'])
        self.assertEqual(kwargs['json']['size'],500)
        self.assertEqual(kwargs['allow_redirects'],False)
        self.assertTrue(arguments[0].endswith('/wazuh-alerts-*/_search'))

    def test_unauthorized_is_clean_error(self):
        responder=Mock(status_code=401)
        with self.assertRaisesRegex(LiveSourceError,'401'):
            fetch_recent_alerts('https://127.0.0.1:9200', 'readonly','secret',
                                requester=Mock(return_value=responder))

    def test_relative_ca_bundle_works_outside_project_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ca = root / '.streamlit' / 'certs' / 'wazuh-root-ca.pem'
            ca.parent.mkdir(parents=True)
            ca.write_text('-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n')
            response = Mock(status_code=200)
            response.json.return_value = {'hits': {'hits': []}}
            requester = Mock(return_value=response)
            old_dir = Path.cwd()
            try:
                with patch('workbench.live.PROJECT_ROOT', root):
                    os.chdir(folder + '/.streamlit')
                    fetch_recent_alerts(
                        'https://127.0.0.1:9200', 'readonly', 'private',
                        verify_tls=True, ca_bundle='.streamlit/certs/wazuh-root-ca.pem',
                        requester=requester,
                    )
            finally:
                os.chdir(old_dir)
            self.assertEqual(requester.call_args.kwargs['verify'], str(ca.resolve()))

    def test_missing_ca_bundle_is_explicit_error(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch('workbench.live.PROJECT_ROOT', Path(folder)):
                with self.assertRaisesRegex(LiveSourceError, 'Cannot load the local Wazuh CA'):
                    fetch_recent_alerts(
                        'https://127.0.0.1:9200', 'readonly', 'private',
                        ca_bundle='.streamlit/certs/not-present.pem',
                        requester=Mock(),
                    )

    def test_non_pem_ca_bundle_is_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / 'bad.pem'
            bad.write_text('not a certificate')
            with self.assertRaisesRegex(LiveSourceError, 'Cannot load the local Wazuh CA'):
                fetch_recent_alerts(
                    'https://127.0.0.1:9200', 'readonly', 'private',
                    ca_bundle=str(bad), requester=Mock(),
                )


if __name__=='__main__':
    unittest.main()
