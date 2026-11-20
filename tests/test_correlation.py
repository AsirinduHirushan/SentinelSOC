"""SOC correlation false-positive and privacy checks; no external services."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workbench.engine import normalize_alert, load_jsonl
from workbench.live import sanitize_hit, fetch_recent_alerts
from workbench.correlation import build_timelines, timeline_report
from unittest.mock import Mock

KEY = 'test-secret-not-for-production-' + 'a'*32


def hit(rule, dt, eventid=None, eventdata=None, syscheck=None, host='001', recordid='1001', hid='abc'):
    event = {
        '_index': 'wazuh-alerts-4.x-2026.11.19', '_id': hid,
        '_source': {
            'timestamp': dt,
            'agent': {'id': host, 'name': 'PRIVATE_HOSTNAME', 'ip': '192.168.2.10'},
            'rule': {'id': rule, 'level': 7, 'description': 'Controlled SOC detection', 'groups': ['lab']},
            'data': {'win': {'system': {'eventID': eventid or '', 'channel':
                     'Microsoft-Windows-Sysmon/Operational' if eventid == '1' else 'Security',
                      'eventRecordID': recordid},
                     'eventdata': eventdata or {}}},
        },
    }
    if syscheck is not None:
        event['_source']['syscheck'] = syscheck
    return event


def n(hit_):
    return normalize_alert(sanitize_hit(hit_, correlation_key=KEY))


class CorrelationTests(unittest.TestCase):
    def test_matching_domain_account_across_auth_and_sysmon(self):
        auth = n(hit('60122', '2026-11-19T09:00:00Z', '4625',
            {'targetUserName': 'SOC-Lab-Test', 'targetDomainName': 'ASIRINDU'}, hid='a'))
        proc = n(hit('100121', '2026-11-19T09:02:00Z', '1',
            {'user': 'asirindu\\SOC-LAB-TEST', 'processGuid': '{one}',
             'commandLine': 'PASSWORD=VERY_SECRET', 'image': 'C:\\Windows\\System32\\cmd.exe'},
            hid='b'))
        file_a = n(hit('550', '2026-11-19T09:04:00Z',
            syscheck={'path': 'C:\\Users\\PERSONAL_NAME\\secret.txt', 'event': 'modified'}, hid='c'))
        result = build_timelines([auth, proc, file_a])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['alert_count'], 3)
        self.assertEqual(set(result[0]['signal_types']), {'Authentication','Process','File Integrity'})
        self.assertGreaterEqual(result[0]['verified_links'], 1)
        text = json.dumps([auth, proc, file_a, result]) + timeline_report(result[0])
        for private in ('PERSONAL_NAME', 'ASIRINDU', 'SOC-Lab-Test', 'VERY_SECRET', '192.168.2.10'):
            self.assertNotIn(private, text)

    def test_different_users_do_not_create_verified_account_link(self):
        auth = n(hit('60122', '2026-11-19T09:00:00Z', '4625',
            {'targetUserName': 'Account-A', 'targetDomainName': 'D'}, hid='a'))
        process = n(hit('100121', '2026-11-19T09:02:00Z', '1',
            {'user': 'D\\Account-B'}, hid='b'))
        chain = build_timelines([auth, process])[0]
        self.assertEqual(chain['verified_links'], 0)
        self.assertEqual(chain['relationship'], 'Endpoint/time context only')

    def test_different_endpoints_never_join(self):
        auth = n(hit('60122', '2026-11-19T09:00:00Z', '4625', hid='a', host='001'))
        process = n(hit('100121', '2026-11-19T09:01:00Z', '1', hid='b', host='002'))
        self.assertEqual(build_timelines([auth, process]), [])

    def test_outside_15_min_never_join(self):
        auth = n(hit('60122', '2026-11-19T09:00:00Z', '4625', hid='a'))
        process = n(hit('100121', '2026-11-19T09:15:01Z', '1', hid='b'))
        self.assertEqual(build_timelines([auth, process]), [])

    def test_duplicate_wazuh_alerts_are_not_distinct_windows_events(self):
        auth1 = n(hit('60122', '2026-11-19T09:00:00Z', '4625', recordid='55', hid='a'))
        auth2 = n(hit('100120', '2026-11-19T09:00:01Z', '4625', recordid='55', hid='b'))
        proc = n(hit('100121', '2026-11-19T09:01:00Z', '1', recordid='77', hid='c'))
        timeline = build_timelines([auth1, auth2, proc])[0]
        self.assertEqual(timeline['alert_count'], 3)
        self.assertEqual(timeline['distinct_source_events'], 2)

    def test_process_guid_lineage_joins_same_endpoint(self):
        a = n(hit('100121', '2026-11-19T09:00:00Z', '1',
                  {'processGuid': '{guid123}', 'user': 'D\\alice'}, hid='a'))
        b = n(hit('60122', '2026-11-19T09:00:05Z', '4625',
                  {'targetUserName': 'bob', 'targetDomainName': 'D'}, hid='b'))
        # ParentProcessGuid is only meaningful between two processes; tests _link explicitly.
        from workbench.correlation import _link
        c = n(hit('92004', '2026-11-19T09:01:00Z', '1',
                  {'parentProcessGuid': '{guid123}', 'user': 'D\\bob'}, hid='c'))
        self.assertEqual(_link(a,c),'Sysmon process GUID')
        self.assertNotEqual(a.get('account_token'), c.get('account_token'))

    def test_account_only_is_medium_not_one_session(self):
        auth = n(hit('60122', '2026-11-19T09:00:00Z', '4625',
            {'targetUserName': 'alice', 'targetDomainName': 'D'}, hid='aa'))
        process = n(hit('100121', '2026-11-19T09:01:00Z', '1',
            {'user': 'D\\alice'}, hid='bb'))
        timeline = build_timelines([auth, process])[0]
        self.assertEqual(timeline['evidence_level'], 'medium')
        self.assertEqual(timeline['medium_links'], 1)
        self.assertEqual(timeline['high_links'], 0)
        self.assertEqual(timeline['links'][0]['evidence'], 'same-account token')
        self.assertIn('single login session', timeline['limitation'])

    def test_guid_link_takes_precedence_over_matching_account(self):
        a = n(hit('100121', '2026-11-19T09:00:00Z', '1',
                  {'processGuid': '{same}', 'user': 'D\\alice'}, hid='aa', recordid='42'))
        b = n(hit('92004', '2026-11-19T09:01:00Z', '1',
                  {'parentProcessGuid': '{same}', 'user': 'D\\alice'}, hid='bb', recordid='43'))
        auth = n(hit('60122', '2026-11-19T09:01:50Z', '4625',
                  {'targetUserName': 'alice', 'targetDomainName': 'D'}, hid='cc', recordid='44'))
        timeline = build_timelines([a,b,auth])[0]
        self.assertEqual(timeline['evidence_level'], 'high')
        self.assertEqual(timeline['high_links'], 1)
        self.assertIn('not a confirmed attack', timeline['limitation'])

    def test_no_entity_match_is_context_only(self):
        auth = n(hit('60122', '2026-11-19T09:00:00Z', '4625',
            {'targetUserName': 'alice', 'targetDomainName': 'D'}, hid='aa'))
        proc = n(hit('100121', '2026-11-19T09:01:00Z', '1',
            {'user': 'D\\bob'}, hid='bb'))
        timeline = build_timelines([auth, proc])[0]
        self.assertEqual(timeline['evidence_level'], 'context')
        self.assertEqual(timeline['context_links'], 1)

    def test_one_source_event_cannot_link_to_itself(self):
        auth = n(hit('60122', '2026-11-19T09:00:00Z', '4625',
            {'targetUserName': 'alice', 'targetDomainName': 'D'}, hid='aa'))
        proc = n(hit('100121', '2026-11-19T09:00:00Z', '1',
            {'user': 'D\\alice'}, hid='bb'))
        # Force identical source-event IDs for this regression case.
        proc['source_event_token'] = auth['source_event_token']
        timeline = build_timelines([auth, proc])[0]
        self.assertEqual(timeline['verified_links'], 0)
        self.assertEqual(timeline['links'], [])

    def test_no_key_no_identifier_generated(self):
        raw = hit('60122', '2026-11-19T09:00:00Z', '4625',
            {'targetUserName': 'private', 'targetDomainName': 'D'}, hid='a')
        sanitized = sanitize_hit(raw)
        self.assertIsNone(sanitized['account_token'])
        self.assertNotIn('private', str(sanitized))

    def test_private_key_change_rotates_tokens(self):
        source = hit('60122', '2026-11-19T09:00:00Z', '4625',
            {'targetUserName': 'PRIVATE', 'targetDomainName': 'D'}, hid='a')
        a = sanitize_hit(source, KEY)
        b = sanitize_hit(source, 'an-entirely-different-private-secret-value')
        self.assertNotEqual(a['account_token'], b['account_token'])

    def test_fetch_queries_necessary_fields_only(self):
        fake = Mock(status_code=200)
        fake.json.return_value = {'hits': {'hits': []}}
        requester = Mock(return_value=fake)
        fetch_recent_alerts('https://127.0.0.1:9200','r','p',
                            requester=requester, correlation_key=KEY)
        body = requester.call_args.kwargs['json']
        self.assertIn('data.win.eventdata.targetUserName', body['_source'])
        self.assertIn('data.win.eventdata.processGuid', body['_source'])
        self.assertIn('syscheck.path', body['_source'])
        self.assertNotIn('data.win.eventdata.commandLine', body['_source'])

    def test_synthetic_fixture_is_explicitly_test_data(self):
        source = Path(__file__).resolve().parent.parent / 'data' / 'synthetic-correlation-demo.jsonl'
        rows, errs = load_jsonl(source)
        self.assertFalse(errs)
        timelines = build_timelines(rows)
        self.assertEqual(len(timelines), 1)
        self.assertEqual(timelines[0]['verified_links'], 2)
        self.assertEqual(len(timelines[0]['signal_types']), 3)
        self.assertNotIn('confirmed incident', timelines[0]['relationship'].lower())

if __name__ == '__main__':
    unittest.main()
