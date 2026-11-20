"""SQLite-only escalation recommendation inbox with idempotent, auditable writes.

The queue is created automatically from local case data, but no network
notifications, Wazuh changes or endpoint commands are performed.
"""
from datetime import datetime, timezone
from workbench.response import response_plan

STATES = ('Queued', 'Acknowledged', 'Escalated', 'Dismissed')
TRANSITIONS = {
    'Queued': {'Acknowledged', 'Escalated', 'Dismissed'},
    'Acknowledged': {'Escalated', 'Dismissed'},
    'Escalated': set(),
    'Dismissed': set(),
}


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def init_queue(conn):
    with conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS escalation_queue (
            case_id TEXT PRIMARY KEY, priority TEXT NOT NULL, score INTEGER NOT NULL,
            reason TEXT NOT NULL, state TEXT NOT NULL, queued_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, reviewer_note TEXT NOT NULL DEFAULT ''
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS escalation_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
            event TEXT NOT NULL, details TEXT NOT NULL, recorded_at TEXT NOT NULL
        )''')


def sync_escalations(conn, cases):
    """Queue new candidates once. Never auto-reopen dismissed/acknowledged items.

    Closed-Benign and already Escalated reviews are not queued anew.
    Score/reason updates don't generate audit spam on each Streamlit rerun.
    """
    init_queue(conn)
    created = 0
    for case in cases:
        plan = response_plan(case)
        if not plan['priority']:
            continue
        cid = case['case_id']
        review = conn.execute('SELECT status FROM reviews WHERE case_id=?', (cid,)).fetchone()
        if review and review[0] in ('Closed - Benign', 'Escalated'):
            continue
        old = conn.execute('SELECT priority,score,reason,state FROM escalation_queue WHERE case_id=?', (cid,)).fetchone()
        now = _utc_now()
        if old is None:
            with conn:
                conn.execute('''INSERT INTO escalation_queue
                    (case_id, priority, score, reason, state, queued_at, updated_at)
                    VALUES (?,?,?,?,?,?,?)''',
                    (cid, plan['priority'], plan['score'], plan['reason'], 'Queued', now, now))
                conn.execute('INSERT INTO escalation_audit(case_id,event,details,recorded_at) VALUES (?,?,?,?)',
                             (cid, 'Auto-queued', plan['reason'], now))
            created += 1
        elif old[:3] != (plan['priority'], plan['score'], plan['reason']):
            # Refresh the evidence snapshot without resetting analyst decisions.
            with conn:
                conn.execute('''UPDATE escalation_queue SET priority=?,score=?,reason=?,updated_at=?
                    WHERE case_id=?''',
                    (plan['priority'], plan['score'], plan['reason'], now, cid))
    return created


def list_escalations(conn, state=None):
    init_queue(conn)
    if state is not None and state not in STATES:
        raise ValueError('Invalid queue state')
    query = 'SELECT case_id,priority,score,reason,state,queued_at,updated_at,reviewer_note FROM escalation_queue'
    args = ()
    if state:
        query += ' WHERE state=?'
        args = (state,)
    query += " ORDER BY CASE priority WHEN 'P1' THEN 0 ELSE 1 END, queued_at DESC, case_id"
    rows = conn.execute(query, args).fetchall()
    keys = ('case_id','priority','score','reason','state','queued_at','updated_at','reviewer_note')
    return [dict(zip(keys, row)) for row in rows]


def escalation_history(conn, case_id):
    init_queue(conn)
    return conn.execute('''SELECT event,details,recorded_at FROM escalation_audit
        WHERE case_id=? ORDER BY id''', (case_id,)).fetchall()


def decide_escalation(conn, case_id, new_state, note):
    """Human decision. Updates review status and both audit trails atomically.

    Notes are mandatory for dismissal and escalation; no automatic containment.
    """
    if new_state not in STATES or new_state == 'Queued':
        raise ValueError('Unsupported decision')
    if not isinstance(note, str) or len(note) > 2000:
        raise ValueError('Note must be <= 2000 characters')
    if new_state in ('Dismissed', 'Escalated') and len(note.strip()) < 8:
        raise ValueError('Provide at least 8 characters explaining this decision')
    init_queue(conn)
    row = conn.execute('SELECT state FROM escalation_queue WHERE case_id=?', (case_id,)).fetchone()
    if not row:
        raise ValueError('Escalation candidate not found')
    old_state = row[0]
    if new_state not in TRANSITIONS.get(old_state, set()):
        raise ValueError(f'Invalid transition {old_state} → {new_state}')
    now = _utc_now()
    with conn:
        conn.execute('UPDATE escalation_queue SET state=?, reviewer_note=?, updated_at=? WHERE case_id=?',
                     (new_state, note.strip(), now, case_id))
        conn.execute('INSERT INTO escalation_audit(case_id,event,details,recorded_at) VALUES (?,?,?,?)',
                     (case_id, f'{old_state} -> {new_state}', note.strip() or 'Acknowledged for analyst review.', now))
        if new_state in ('Acknowledged', 'Escalated'):
            new_review = 'Investigating' if new_state == 'Acknowledged' else 'Escalated'
            existing = conn.execute('SELECT status,notes FROM reviews WHERE case_id=?', (case_id,)).fetchone()
            if not existing or existing[0] not in ('Closed - Benign', 'Escalated'):
                # Keep the previous analyst notes, rather than silently replacing them.
                previous_notes = existing[1] if existing else ''
                new_notes = (previous_notes + '\n' + note.strip()).strip()[:5000] if note.strip() else previous_notes
                conn.execute('''INSERT INTO reviews (case_id,status,notes,updated_at)
                    VALUES (?,?,?,?) ON CONFLICT(case_id) DO UPDATE SET
                    status=excluded.status,notes=excluded.notes,updated_at=excluded.updated_at''',
                    (case_id, new_review, new_notes, now))
                conn.execute('INSERT INTO audit(case_id,status,updated_at) VALUES (?,?,?)',
                             (case_id, new_review, now))
    return new_state
