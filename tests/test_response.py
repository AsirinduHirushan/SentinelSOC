"""Core response policy tests; offline/standard library."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workbench.response import response_plan, response_report_section


def make_case(level=5, score=35, sources=None, category='Other', rid='550'):
    sources = sources if sources is not None else ['a', 'b']
    return {'case_id': 'CASE-TEST', 'category': category, 'score': score,
            'alerts':[{'level':level,'rule_id':rid,'source_event_token':s} for s in sources]}


class ResponsePolicyTests(unittest.TestCase):
    def test_critical_single_record_queued_p1(self):
        self.assertEqual(response_plan(make_case(14, 56, ['a']))['priority'], 'P1')

    def test_high_rule_queued_p2(self):
        self.assertEqual(response_plan(make_case(12, 48, ['a']))['priority'], 'P2')

    def test_score_with_independent_sources_p2(self):
        self.assertEqual(response_plan(make_case(9, 70, ['a','b']))['priority'], 'P2')

    def test_score_with_independent_sources_p1(self):
        self.assertEqual(response_plan(make_case(10, 90, ['a','b']))['priority'], 'P1')

    def test_score_no_source_identifiers_not_autoqueued(self):
        self.assertIsNone(response_plan(make_case(5, 99, [None,None]))['priority'])

    def test_source_dedup(self):
        p = response_plan(make_case(7, 85, ['a','a']))
        self.assertEqual(p['distinct_sources'], 1)
        self.assertIsNone(p['priority'])

    def test_auth_includes_account_review(self):
        actions = response_plan(make_case(5,40,['a'], 'Authentication'))['actions']
        self.assertTrue(any('login-failure' in row['action'] for row in actions))
        self.assertTrue(any(row['approval'] for row in actions))

    def test_fim_includes_file_validation(self):
        actions = response_plan(make_case(5,40,['a'], 'File Integrity'))['actions']
        self.assertTrue(any('file change' in row['action'] for row in actions))

    def test_untrusted_descriptions_not_in_report(self):
        case = make_case(12,80,['a'])
        case['alerts'][0].update({'description':'secret-password','raw_log':'private-ip'})
        result = response_report_section(case)
        self.assertNotIn('secret-password', result)
        self.assertNotIn('private-ip', result)
        self.assertIn('human approval', result)

    def test_routine_review_not_confident_benign(self):
        result = response_report_section(make_case())
        self.assertIn('Routine review', result)
        self.assertIn('not proof of compromise', result)

if __name__ == '__main__': unittest.main()
