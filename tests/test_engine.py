import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workbench.engine import load_jsonl, normalize_alert, group_cases, markdown_case_report
from workbench.state import connect, save_review, get_review, review_history


def a(time, rule='60122', account=None, agent='lab-endpoint', level=5):
    rec = {'timestamp':time,'rule_id':rule,'level':level,'agent':agent,'description':'Lab test','groups':[]}
    if account is not None:
        rec['account_token'] = account
    return normalize_alert(rec)


class WorkbenchTests(unittest.TestCase):
    def test_source_file_loads(self):
        source = Path(__file__).resolve().parent.parent/'data'/'sentinelsoc-alerts.jsonl'
        alerts, errors = load_jsonl(source)
        self.assertEqual(len(alerts), 30)
        self.assertEqual(len(errors), 0)

    def test_bad_lines_and_dedup(self):
        with TemporaryDirectory() as tmp:
            path=Path(tmp)/'test.jsonl'
            good={'timestamp':'2026-11-19T12:00:00+00:00','rule_id':'60122','level':5}
            path.write_text(json.dumps(good)+'\n'+json.dumps(good)+'\n{bad}\n')
            events, errors=load_jsonl(path)
            self.assertEqual((len(events),len(errors)), (1,1))

    def test_rejects_invalid_level(self):
        with self.assertRaises(ValueError):
            a('2026-11-19T12:00:00+00:00', level=-1)

    def test_three_logins_does_not_invent_custom_rule(self):
        events=[a(f'2026-11-19T12:00:{n:02d}+00:00') for n in (0,20,40)]
        cases=group_cases(events)
        self.assertEqual(cases[0]['alert_count'],3)
        self.assertNotIn('100120', cases[0]['rule_counts'])
        self.assertIn('NOT verified', cases[0]['limitation'])

    def test_accounts_separate_when_pseudonymized(self):
        events=[a(f'2026-11-19T12:00:{n:02d}+00:00', account=who) for n,who in
                [(0,'acct_A'),(10,'acct_B'),(20,'acct_A'),(30,'acct_B')]]
        cases=group_cases(events)
        self.assertEqual(len(cases),2)
        self.assertEqual(sorted(c['alert_count'] for c in cases), [2,2])

    def test_time_gap_splits(self):
        events=[a('2026-11-19T12:00:00+00:00'), a('2026-11-19T12:25:00+00:00')]
        self.assertEqual(len(group_cases(events)),2)

    def test_score_explained_and_capped(self):
        events=[a('2026-11-19T12:00:00+00:00',level=15),a('2026-11-19T12:00:10+00:00',rule='100120',level=10)]
        case=group_cases(events)[0]
        self.assertLessEqual(case['score'],100)
        self.assertGreater(case['score'],0)
        self.assertEqual(case['score'],sum(v for _,v in case['score_factors']))

    def test_report_contains_uncertainty(self):
        case=group_cases([a('2026-11-19T12:00:00+00:00')])[0]
        txt=markdown_case_report(case)
        self.assertIn('Account-level correlation is NOT verified',txt)
        self.assertIn('not prove an attack',txt)

    def test_review_and_audit(self):
        with TemporaryDirectory() as d:
            conn=connect(Path(d)/'cases.sqlite3')
            save_review(conn,'CASE-TEST','Investigating','Controlled lab activity.')
            save_review(conn,'CASE-TEST','Closed - Benign','Confirmed local test.')
            self.assertEqual(get_review(conn,'CASE-TEST')['status'],'Closed - Benign')
            self.assertEqual(len(review_history(conn,'CASE-TEST')),2)
            with self.assertRaises(ValueError):
                save_review(conn,'CASE-TEST','Malicious','Unsupported verdict')
            conn.close()


if __name__=='__main__':
    unittest.main()
