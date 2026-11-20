"""Regression tests for conservative ATT&CK technique suggestions."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workbench.attack_mapping import map_alerts, attack_report_section, technique_url


class MappingTests(unittest.TestCase):
    def test_known_rule_mapping(self):
        m = map_alerts([{'rule_id':'92021','alert_id':'e1','source_event_token':'src1'}])
        self.assertEqual([x['technique_id'] for x in m], ['T1059.001','T1070.004'])

    def test_isolated_failure_not_bruteforce(self):
        self.assertEqual(map_alerts([{'rule_id':'60122','alert_id':'x'}]), [])

    def test_fim_modification_not_indicator_removal(self):
        self.assertEqual(map_alerts([{'rule_id':'594','alert_id':'y','file_action':'modified'},
                                     {'rule_id':'550','alert_id':'z'}]), [])

    def test_ambiguous_admin_location_unmapped(self):
        self.assertEqual(map_alerts([{'rule_id':'92066','alert_id':'x'}]), [])

    def test_multiple_rules_same_source_do_not_double_count(self):
        m=map_alerts([{'rule_id':'92021','alert_id':'e1','source_event_token':'same'},
                      {'rule_id':'92021','alert_id':'e2','source_event_token':'same'}])
        self.assertTrue(m)
        self.assertTrue(all(x['source_count']==1 for x in m))

    def test_never_invent_mapping_from_text(self):
        self.assertEqual(map_alerts([{'rule_id':'9999','description':'PowerShell file deletion behavior matched',
                                      'alert_id':'z'}]), [])

    def test_privacy_no_untrusted_text_in_report(self):
        m=attack_report_section([{'rule_id':'100120','alert_id':'e','description':'s3cretpass',
                                  'account_token':'acct_123','file_path':'C:/secret/private'}])
        self.assertIn('T1110',m)
        for private in ('s3cretpass','acct_123','C:/secret/private'):
            self.assertNotIn(private,m)

    def test_report_with_no_matches_is_explicit(self):
        self.assertIn('No mapping', attack_report_section([{'rule_id':'550','alert_id':'e'}]))

    def test_official_urls(self):
        self.assertEqual(technique_url('T1059.001'),'https://attack.mitre.org/techniques/T1059/001/')
        with self.assertRaises(ValueError): technique_url('T9999')

    def test_empty(self):
        self.assertEqual(map_alerts([]),[])

    def test_rule_process_discovery(self):
        self.assertEqual(map_alerts([{'rule_id':'100121','alert_id':'p'}])[0]['technique_id'], 'T1033')

    def test_rule_repeated_logins(self):
        self.assertEqual(map_alerts([{'rule_id':'100120','alert_id':'p'}])[0]['technique_id'], 'T1110')

    def test_technique_sorted_deterministic(self):
        a=[{'rule_id':'92021','alert_id':'p'},{'rule_id':'100120','alert_id':'q'}]
        self.assertEqual(map_alerts(a), map_alerts(list(reversed(a))))


if __name__=='__main__': unittest.main()
