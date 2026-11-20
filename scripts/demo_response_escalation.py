"""Offline smoke test: synthetic P1 example, isolated temporary SQLite database.

Does not read Wazuh, write to SentinelSOC's live triage database, send messages,
or change any endpoint.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from workbench.state import connect, get_review
from workbench.response import response_plan
from workbench.escalation import sync_escalations, list_escalations, decide_escalation

example = {
    'case_id': 'CASE-DEMO-P1', 'category': 'Process Discovery', 'score': 89,
    'alerts': [
        {'level':14,'rule_id':'92021','source_event_token':'demo_1'},
        {'level':10,'rule_id':'92031','source_event_token':'demo_2'},
    ],
}
with TemporaryDirectory(prefix='sentinelsoc_response_demo_') as temp:
    db = connect(Path(temp)/'synthetic-demo.sqlite3')
    plan = response_plan(example)
    created = sync_escalations(db,[example])
    print(f"SYNTHETIC TEST ONLY: {example['case_id']} => {plan['priority']} | queued={created}")
    print('Inbox before decision:', [(x['case_id'], x['state']) for x in list_escalations(db)])
    decide_escalation(db,example['case_id'],'Acknowledged','Reviewing synthetic incident.')
    print('Inbox after acknowledgment:', [(x['case_id'], x['state']) for x in list_escalations(db)])
    print('Analyst review status:', get_review(db,example['case_id'])['status'])
    print('No live alerts or project database were touched.')
    db.close()
