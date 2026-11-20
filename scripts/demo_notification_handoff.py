"""Self-contained demonstration: NO email/webhook/network traffic sent."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workbench.state import connect
from workbench.escalation import decide_escalation,sync_escalations
from workbench.notifications import send_approved_handoff,delivery_rows,delivery_audit

case = {'case_id':'CASE-TESTHANDOFF', 'score':74, 'category':'File Integrity',
        'alerts':[{'rule_id':'550','level':13,'source_event_token':'demo-source'}]}
settings = {'enabled':True, 'webhook':{'url':'https://hooks.example.org/demo', 'label':'Demo receiver', 'min_priority':'P2'}}
with TemporaryDirectory() as folder:
    db=connect(Path(folder)/'demo.sqlite3')
    sync_escalations(db,[case])
    decide_escalation(db,case['case_id'],'Escalated','Demo lab case reviewed and approved for handoff.')
    calls=[]
    def fake_network(config,payload,delivery_id):
        calls.append(payload['case_id'])
        print('SIMULATED provider acceptance:',payload['case_id'],'(nothing sent)')
    result=send_approved_handoff(db,case['case_id'],'webhook','Please review the simulated case.',
                                 settings,transport=fake_network)
    print('State:',result['state'])
    print('Saved rows:',len(delivery_rows(db)))
    print('Audit entries:',len(delivery_audit(db,case['case_id'])))
    try:
        send_approved_handoff(db,case['case_id'],'webhook','Please review the simulated case.',
                              settings,transport=fake_network)
    except ValueError as ex:
        print('Duplicate blocked:',type(ex).__name__)
    print('Simulated send calls:',len(calls))
    db.close()
