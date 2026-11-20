"""Safe notification / handoff regression tests; no real network calls."""
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from workbench.state import connect
from workbench.escalation import sync_escalations, decide_escalation
from workbench.notifications import (
    NotificationError, DeliveryRejected, delivery_audit, delivery_rows, format_handoff,
    handoff_preview, send_approved_handoff, validate_channel_config,
)

WEBHOOK = {'enabled':True, 'webhook':{'url':'https://hooks.example.org/events','label':'SOC team webhook'}}
SMTP = {'enabled':True, 'email':{'host':'smtp.example.org','port':465,'security':'ssl',
        'from_email':'soc@example.org','to_email':'analyst@example.org',
        'username':'soc@example.org','password':'SECRET_PASSWORD'}}


def fake_case():
    return {'case_id':'CASE-123ABC', 'score':68, 'category':'File Integrity',
            'alerts':[{'level':12,'rule_id':'550','source_event_token':'source_1'}]}


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = connect(Path(self.tmp.name)/'triage.sqlite3')
        sync_escalations(self.db,[fake_case()])

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def escalate(self):
        decide_escalation(self.db,'CASE-123ABC','Escalated','Reviewed and assigned to response analyst.')

    def test_does_not_send_for_queued_case(self):
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','webhook','Escalate for review.',WEBHOOK,
                                  transport=lambda *a: self.fail('must not send'))
        self.assertFalse(delivery_rows(self.db))

    def test_does_not_send_for_acknowledged_case(self):
        decide_escalation(self.db,'CASE-123ABC','Acknowledged','Review started.')
        with self.assertRaises(NotificationError):
            handoff_preview(self.db,'CASE-123ABC','Escalate for review.')

    def test_delivered_exactly_once_per_channel(self):
        self.escalate()
        sent=[]
        sender=lambda cfg,payload,delivery_id: sent.append((cfg,payload,delivery_id))
        first = send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate this alert.',WEBHOOK,transport=sender)
        self.assertEqual(first['state'],'Accepted')
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate this alert.',WEBHOOK,transport=sender)
        self.assertEqual(len(sent),1)
        self.assertEqual(len(delivery_rows(self.db)),1)
        self.assertEqual(delivery_rows(self.db)[0]['attempts'],1)
        self.assertEqual([x[1] for x in delivery_audit(self.db,'CASE-123ABC')],['Approved send attempt','Accepted'])

    def test_independent_channels(self):
        self.escalate()
        send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,transport=lambda *a:None)
        send_approved_handoff(self.db,'CASE-123ABC','email','Please investigate.',SMTP,transport=lambda *a:None)
        self.assertEqual(len(delivery_rows(self.db)),2)

    def test_definite_rejection_manual_retry(self):
        self.escalate()
        def reject(*args): raise DeliveryRejected('No sender.')
        result=send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,transport=reject)
        self.assertEqual(result['state'],'Failed')
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,transport=lambda *a:None)
        result=send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,
                                     retry=True,transport=lambda *a:None)
        self.assertEqual(result['state'],'Accepted')
        self.assertEqual(delivery_rows(self.db)[0]['attempts'],2)

    def test_uncertain_requires_explicit_confirmation(self):
        self.escalate()
        def maybe_sent(*args): raise TimeoutError('possibly delivered')
        result=send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,transport=maybe_sent)
        self.assertEqual(result['state'],'Uncertain')
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,
                                 retry=True,transport=lambda *a:None)
        result=send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,
                                     retry=True, verified_not_delivered=True,transport=lambda *a:None)
        self.assertEqual(result['state'],'Accepted')

    def test_crashed_pending_send_is_not_retried(self):
        self.escalate()
        self._init()
        self.db.execute("INSERT INTO notification_deliveries(case_id,channel,status,attempts,target_label,last_code,updated_at,created_at) VALUES (?,?,?,?,?,?,?,?)",
                        ('CASE-123ABC','webhook','Sending',1,'Webhook','','2026-11-20','2026-11-20'))
        self.db.commit()
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,
                                   transport=lambda *a:self.fail('duplicate'))

    def _init(self):
        from workbench.notifications import init_notifications
        init_notifications(self.db)
        return True

    def test_missing_config_disabled(self):
        self.escalate()
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',{'enabled':False,'webhook':{'url':'https://hooks.example.org/events'}},transport=lambda *a:self.fail('send'))
        self.assertEqual(delivery_rows(self.db),[])

    def test_reject_non_https_and_private_ips(self):
        for url in ('http://hooks.example.org/x', 'https://127.0.0.1/x',
                    'https://192.168.1.100/x', 'https://user:pass@hooks.example.org/x',
                    'https://hooks.example.org:8080/x'):
            with self.subTest(url=url),self.assertRaises(NotificationError):
                validate_channel_config({'enabled':True,'webhook':{'url':url}},'webhook')

    def test_smtp_credentials_do_not_persist(self):
        self.escalate()
        result=send_approved_handoff(self.db,'CASE-123ABC','email','Please investigate.',SMTP,
                                     transport=lambda cfg,*args: self.assertEqual(cfg['password'],'SECRET_PASSWORD'))
        self.assertEqual(result['state'],'Accepted')
        full=' '.join(str(row) for row in self.db.execute('SELECT * FROM notification_deliveries').fetchall())
        self.assertNotIn('SECRET_PASSWORD', full)
        self.assertNotIn('analyst@example.org', full)

    def test_payload_sanitized_and_report(self):
        self.escalate()
        payload=handoff_preview(self.db,'CASE-123ABC','Please investigate and validate the alert.')
        self.assertEqual(payload['event'],'sentinelsoc.analyst_approved_handoff')
        self.assertIn('not proof',format_handoff(payload).lower())
        self.assertNotIn('SECRET_PASSWORD',format_handoff(payload))

    def test_no_sensitive_raw_notes_carried_automatically(self):
        self.escalate()
        self.db.execute("UPDATE reviews SET notes='SENSITIVE DO NOT SEND' WHERE case_id='CASE-123ABC'")
        payload=handoff_preview(self.db,'CASE-123ABC','Please investigate the incident.')
        self.assertNotIn('SENSITIVE DO NOT SEND',str(payload))

    def test_handoff_note_length(self):
        self.escalate()
        with self.assertRaises(NotificationError):
            handoff_preview(self.db,'CASE-123ABC','short')
        with self.assertRaises(NotificationError):
            handoff_preview(self.db,'CASE-123ABC','x'*501)

    def test_cannot_send_arbitrary_case(self):
        self.escalate()
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-OTHER','webhook','Please investigate.',WEBHOOK,
                                  transport=lambda *a:self.fail('must not send'))


    def test_policy_prevents_p2_email_to_p1_only(self):
        self.escalate()
        cfg={**SMTP,'email':{**SMTP['email'],'min_priority':'P1'}}
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','email','Please investigate.',cfg,
                                  transport=lambda *a:self.fail('must not send'))
        self.assertFalse(delivery_rows(self.db))

    def test_stale_send_manual_recovery_without_retry(self):
        from workbench.notifications import init_notifications, mark_stale_sending_uncertain
        self.escalate()
        init_notifications(self.db)
        self.db.execute("INSERT INTO notification_deliveries(case_id,channel,status,attempts,target_label,last_code,updated_at,created_at) VALUES (?,?,?,?,?,?,?,?)",
                        ('CASE-123ABC','webhook','Sending',1,'Webhook','','2020-01-01T00:00:00+00:00','2020-01-01T00:00:00+00:00'))
        self.db.commit()
        self.assertTrue(mark_stale_sending_uncertain(self.db,'CASE-123ABC','webhook'))
        self.assertEqual(delivery_rows(self.db)[0]['status'],'Uncertain')
        with self.assertRaises(NotificationError):
            send_approved_handoff(self.db,'CASE-123ABC','webhook','Please investigate.',WEBHOOK,
                                   retry=True,transport=lambda *a:self.fail('must not send'))


if __name__=='__main__':
    unittest.main()
