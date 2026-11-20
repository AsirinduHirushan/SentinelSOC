"""Escalation persistence and decision audit tests."""
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workbench.state import connect, get_review
from workbench.escalation import sync_escalations, list_escalations, escalation_history, decide_escalation
from workbench.response import response_plan


def case(cid='CASE-X', severity=12, score=60):
    return {'case_id':cid,'category':'File Integrity','score':score,
            'alerts':[{'level':severity, 'rule_id':'550', 'source_event_token':'tok_a'}]}


class InboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.conn = connect(Path(self.tmp.name)/'triage.sqlite3')

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_queue_once_even_on_multiple_syncs(self):
        c = case()
        self.assertEqual(sync_escalations(self.conn,[c]),1)
        self.assertEqual(sync_escalations(self.conn,[c]),0)
        self.assertEqual(len(list_escalations(self.conn)),1)
        self.assertEqual(len(escalation_history(self.conn,'CASE-X')),1)

    def test_no_low_priority_queue(self):
        self.assertEqual(sync_escalations(self.conn,[case(severity=4,score=20)]),0)
        self.assertEqual(len(list_escalations(self.conn)),0)

    def test_acknowledge_updates_case_review_and_both_audits(self):
        sync_escalations(self.conn,[case()])
        decide_escalation(self.conn,'CASE-X','Acknowledged','Reviewing next.')
        self.assertEqual(get_review(self.conn,'CASE-X')['status'],'Investigating')
        self.assertEqual(len(escalation_history(self.conn,'CASE-X')),2)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM audit').fetchone()[0],1)

    def test_escalate_requires_reason_and_sets_status(self):
        sync_escalations(self.conn,[case()])
        with self.assertRaises(ValueError):
            decide_escalation(self.conn,'CASE-X','Escalated','')
        decide_escalation(self.conn,'CASE-X','Escalated','Verified response lead contacted.')
        self.assertEqual(get_review(self.conn,'CASE-X')['status'],'Escalated')

    def test_dismiss_does_not_mark_benign(self):
        sync_escalations(self.conn,[case()])
        decide_escalation(self.conn,'CASE-X','Dismissed','Expected lab change.')
        self.assertEqual(get_review(self.conn,'CASE-X')['status'],'New')
        self.assertEqual(sync_escalations(self.conn,[case()]),0)
        self.assertEqual(list_escalations(self.conn)[0]['state'],'Dismissed')

    def test_invalid_transition(self):
        sync_escalations(self.conn,[case()])
        decide_escalation(self.conn,'CASE-X','Dismissed','Expected lab change.')
        with self.assertRaises(ValueError):
            decide_escalation(self.conn,'CASE-X','Escalated','This should not work.')

    def test_previous_notes_preserved(self):
        from workbench.state import save_review
        sync_escalations(self.conn,[case()])
        save_review(self.conn,'CASE-X','Investigating','First note.')
        decide_escalation(self.conn,'CASE-X','Escalated','Escalate with supporting evidence.')
        self.assertIn('First note.',get_review(self.conn,'CASE-X')['notes'])

    def test_already_closed_benign_not_queued(self):
        from workbench.state import save_review
        save_review(self.conn,'CASE-X','Closed - Benign','Verified benign local test')
        self.assertEqual(sync_escalations(self.conn,[case()]),0)

    def test_priority_change_refreshes_in_place(self):
        sync_escalations(self.conn,[case(severity=12,score=60)])
        sync_escalations(self.conn,[case(severity=15,score=90)])
        rows = list_escalations(self.conn)
        self.assertEqual((len(rows),rows[0]['priority'],rows[0]['score']), (1,'P1',90))
        self.assertEqual(len(escalation_history(self.conn,'CASE-X')),1)

    def test_missing_id_rejected(self):
        with self.assertRaises(ValueError):
            decide_escalation(self.conn,'missing','Acknowledged','')

    def test_final_queue_not_reopened_by_sync(self):
        sync_escalations(self.conn,[case()])
        decide_escalation(self.conn,'CASE-X','Escalated','Evidence submitted to supervisor.')
        sync_escalations(self.conn,[case(severity=15,score=90)])
        self.assertEqual(list_escalations(self.conn)[0]['state'],'Escalated')

if __name__ == '__main__': unittest.main()
