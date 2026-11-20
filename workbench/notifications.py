"""Human-approved, idempotent SentinelSOC incident handoffs.

NO background worker or automatic external transmission. Network I/O only after a
Streamlit analyst explicitly approves delivery for an already escalated live case.
The local SQLite log stores metadata, never provider credentials or message bodies.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from email.utils import parseaddr
from hashlib import sha256
from ipaddress import ip_address
import json
import re
import smtplib
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

CHANNELS = ('webhook', 'email')
STATES = ('Sending', 'Accepted', 'Failed', 'Uncertain')


class NotificationError(ValueError):
    """Safe, user-facing policy or configuration error."""


class DeliveryRejected(Exception):
    """Definite provider rejection; explicitly retryable after correction."""


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def init_notifications(conn):
    with conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS notification_deliveries (
            case_id TEXT NOT NULL, channel TEXT NOT NULL,
            status TEXT NOT NULL, attempts INTEGER NOT NULL,
            target_label TEXT NOT NULL, last_code TEXT NOT NULL,
            updated_at TEXT NOT NULL, created_at TEXT NOT NULL,
            PRIMARY KEY (case_id, channel)
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS notification_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL, channel TEXT NOT NULL,
            event TEXT NOT NULL, detail TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )''')


def delivery_rows(conn, case_id=None):
    init_notifications(conn)
    q = ('SELECT case_id,channel,status,attempts,target_label,last_code,updated_at,created_at '
         'FROM notification_deliveries')
    vals = ()
    if case_id is not None:
        q += ' WHERE case_id=?'
        vals = (case_id,)
    q += ' ORDER BY updated_at DESC, case_id, channel'
    keys = ('case_id', 'channel', 'status', 'attempts', 'target_label', 'last_code',
            'updated_at', 'created_at')
    return [dict(zip(keys, r)) for r in conn.execute(q, vals).fetchall()]


def delivery_audit(conn, case_id):
    init_notifications(conn)
    return conn.execute('''SELECT channel,event,detail,recorded_at FROM notification_audit
        WHERE case_id=? ORDER BY id''', (case_id,)).fetchall()


def _clean_value(value, *, limit=120):
    text = str(value or '').strip()
    text = re.sub(r'[\x00-\x1f\x7f]', ' ', text)
    return text[:limit]


def _valid_email(addr):
    if not isinstance(addr, str) or not addr or '\r' in addr or '\n' in addr:
        return False
    display, parsed = parseaddr(addr)
    return not display and addr == parsed and '@' in addr and ' ' not in addr and len(addr) <= 254


def validate_channel_config(settings, channel):
    """Only configured targets are allowed. Never take destinations from alerts or UI."""
    if channel not in CHANNELS:
        raise NotificationError('Unsupported notification channel.')
    if not settings or settings.get('enabled') is not True:
        raise NotificationError('Notification sending is disabled. Enable [notifications] explicitly in local Streamlit secrets.')
    cfg = settings.get(channel) or {}
    minimum = cfg.get('min_priority','P2')
    if minimum not in ('P1','P2'):
        raise NotificationError('min_priority must be P1 or P2.')
    if channel == 'webhook':
        url = cfg.get('url') or ''
        try:
            p = urlsplit(url)
            port = p.port
        except (ValueError, TypeError):
            raise NotificationError('Webhook URL must be a valid HTTPS URL.') from None
        try:
            addr = ip_address(p.hostname or '')
        except ValueError:
            addr = None  # Ordinary DNS name (operator-controlled secrets only).
        if (p.scheme != 'https' or not p.hostname or p.username or p.password
                or p.fragment or (port is not None and port != 443)
                or (addr is not None and not addr.is_global)):
            raise NotificationError('Webhook must be a public HTTPS destination configured by the operator.')
        if len(url) > 2048:
            raise NotificationError('Webhook URL too long.')
        return {'url': url, 'target_label': _clean_value(cfg.get('label') or 'Configured HTTPS webhook', limit=60),
                'min_priority': minimum}
    host = cfg.get('host') or ''
    if not isinstance(host, str) or not host.strip() or any(c in host for c in '/\\\r\n@ '):
        raise NotificationError('Configure a valid SMTP host in local secrets.')
    try:
        port = int(cfg.get('port', 465))
    except (TypeError, ValueError):
        raise NotificationError('SMTP port must be an integer.') from None
    security = cfg.get('security', 'ssl')
    if security not in ('ssl', 'starttls') or not 1 <= port <= 65535:
        raise NotificationError('SMTP requires ssl or starttls with a valid port.')
    sender, receiver = cfg.get('from_email'), cfg.get('to_email')
    if not _valid_email(sender) or not _valid_email(receiver):
        raise NotificationError('Configure valid from_email and to_email addresses.')
    username, password = cfg.get('username'), cfg.get('password')
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise NotificationError('SMTP username and password must be set in local secrets.')
    return {'host': host, 'port': port, 'security': security, 'from_email': sender,
            'to_email': receiver, 'username': username, 'password': password,
            'target_label': 'Configured incident-response email', 'min_priority': minimum}


def _message(case_id, priority, score, reason, analyst_note):
    """Bounded, sanitized summary; deliberately excludes raw alerts and case notes."""
    if not re.fullmatch(r'CASE-[A-Za-z0-9_-]{1,48}', case_id):
        raise NotificationError('Unexpected case ID; unable to send.')
    if priority not in ('P1', 'P2'):
        raise NotificationError('Only P1/P2 escalations can be delivered.')
    if not isinstance(analyst_note, str) or not 8 <= len(analyst_note.strip()) <= 500:
        raise NotificationError('Enter an 8–500 character handoff summary before sending.')
    if any(c in analyst_note for c in '\r\x00'):
        raise NotificationError('Handoff summary contains an unsupported control character.')
    return {
        'event': 'sentinelsoc.analyst_approved_handoff',
        'case_id': case_id, 'priority': priority, 'heuristic_score': int(score),
        'assessment': 'Analyst approved escalation for investigation; compromise not confirmed',
        'triage_reason': _clean_value(reason, limit=320),
        'analyst_handoff': analyst_note.strip(),
        'note': 'No raw logs, credentials, IP addresses, file paths or command lines included.',
    }


def handoff_preview(conn, case_id, analyst_note):
    from workbench.escalation import init_queue
    init_queue(conn)
    row = conn.execute('SELECT priority,score,reason,state FROM escalation_queue WHERE case_id=?', (case_id,)).fetchone()
    if not row or row[3] != 'Escalated':
        raise NotificationError('An analyst must first choose Escalate in the Escalation inbox.')
    review = conn.execute('SELECT status FROM reviews WHERE case_id=?', (case_id,)).fetchone()
    if not review or review[0] != 'Escalated':
        raise NotificationError('The analyst review must also be Escalated before sending.')
    return _message(case_id, row[0], row[1], row[2], analyst_note)


def format_handoff(payload):
    return ('SentinelSOC — analyst-approved incident handoff\n\n'
            f"Case: {payload['case_id']}\nPriority: {payload['priority']}\n"
            f"Heuristic score: {payload['heuristic_score']}/100\n"
            f"Assessment: {payload['assessment']}\n"
            f"Triage reason: {payload['triage_reason']}\n"
            f"Analyst handoff: {payload['analyst_handoff']}\n\n"
            'This is an investigation request, not proof of compromise.\n')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DeliveryRejected('The configured webhook redirected the request.')


def _send_webhook(config, payload, delivery_id):
    body = json.dumps(payload, ensure_ascii=True).encode('utf-8')
    req = urllib.request.Request(
        config['url'], data=body, method='POST', headers={
            'Content-Type': 'application/json',
            'User-Agent': 'SentinelSOC/3 notification-handoff',
            'X-SentinelSOC-Delivery-ID': delivery_id,
        })
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(req, timeout=8) as res:
            if not 200 <= res.status < 300:
                raise DeliveryRejected('Webhook rejected the request.')
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500:
            raise DeliveryRejected('Webhook rejected the request.') from None
        raise  # 5xx may have accepted action, treat as uncertain


def _send_email(config, payload, delivery_id):
    msg = EmailMessage()
    msg['Subject'] = f"[SentinelSOC {payload['priority']}] Analyst-approved handoff {payload['case_id']}"
    msg['From'] = config['from_email']
    msg['To'] = config['to_email']
    msg['X-SentinelSOC-Delivery-ID'] = delivery_id
    msg.set_content(format_handoff(payload))
    ctx = ssl.create_default_context()
    kind = smtplib.SMTP_SSL if config['security'] == 'ssl' else smtplib.SMTP
    with kind(config['host'], config['port'], timeout=8,
              **({'context': ctx} if config['security'] == 'ssl' else {})) as server:
        if config['security'] == 'starttls':
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
        server.login(config['username'], config['password'])
        rejected = server.send_message(msg)
        if rejected:
            raise DeliveryRejected('SMTP rejected recipient(s).')


def send_approved_handoff(conn, case_id, channel, analyst_note, settings, *, retry=False,
                          verified_not_delivered=False, transport=None):
    """Explicit human-driven send. Returns a metadata-only result, never logs secrets.

    Accepted rows cannot be resent. Failure is manually retryable. A possible
    network timeout is Uncertain and requires an extra operator confirmation.
    """
    cfg = validate_channel_config(settings, channel)
    payload = handoff_preview(conn, case_id, analyst_note)
    if cfg['min_priority'] == 'P1' and payload['priority'] != 'P1':
        raise NotificationError('Notification policy permits P1 cases only for this channel.')
    init_notifications(conn)
    now = utc_now()
    # Acquire the claim transactionally; ensure Streamlit reruns/double-clicks
    # do not cause concurrent external delivery for the same case + channel.
    try:
        conn.execute('BEGIN IMMEDIATE')
        existing = conn.execute('SELECT status,attempts FROM notification_deliveries WHERE case_id=? AND channel=?',
                                (case_id, channel)).fetchone()
        if existing:
            status, attempts = existing
            if status in ('Accepted', 'Sending'):
                conn.commit()
                raise NotificationError('This case/channel is already accepted or currently sending; no duplicate sent.')
            if not retry:
                conn.commit()
                raise NotificationError('Previous delivery failed or was uncertain. Review history and explicitly retry.')
            if status == 'Uncertain' and not verified_not_delivered:
                conn.commit()
                raise NotificationError('Delivery uncertain; verify with the recipient before approving a retry.')
            conn.execute('''UPDATE notification_deliveries SET status='Sending', attempts=?,
                last_code='', updated_at=?, target_label=? WHERE case_id=? AND channel=?''',
                (attempts+1,now,cfg['target_label'],case_id,channel))
        else:
            conn.execute('''INSERT INTO notification_deliveries
                (case_id,channel,status,attempts,target_label,last_code,updated_at,created_at)
                VALUES (?,?,?,?,?,?,?,?)''',
                (case_id,channel,'Sending',1,cfg['target_label'],'',now,now))
        conn.execute('''INSERT INTO notification_audit (case_id,channel,event,detail,recorded_at)
            VALUES (?,?,?,?,?)''', (case_id,channel,'Approved send attempt','Explicit analyst action',now))
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    delivery_id = sha256((case_id + '\0' + channel).encode('utf-8')).hexdigest()[:24]
    sender = transport if transport is not None else (_send_webhook if channel == 'webhook' else _send_email)
    try:
        sender(cfg, payload, delivery_id)
    except DeliveryRejected:
        state, code = 'Failed', 'provider-rejected'
    except (Exception,):
        # A timeout or disconnection can happen AFTER a remote server accepts
        # the request. No automatic retry is safe in this situation.
        state, code = 'Uncertain', 'delivery-not-confirmed'
    else:
        state, code = 'Accepted', 'provider-accepted'
    recorded = utc_now()
    with conn:
        conn.execute('''UPDATE notification_deliveries SET status=?,last_code=?,updated_at=?
            WHERE case_id=? AND channel=? AND status='Sending' ''',
            (state,code,recorded,case_id,channel))
        conn.execute('''INSERT INTO notification_audit (case_id,channel,event,detail,recorded_at)
            VALUES (?,?,?,?,?)''', (case_id,channel,state,code,recorded))
    return {'case_id':case_id, 'channel':channel, 'state':state, 'code':code}


def mark_stale_sending_uncertain(conn, case_id, channel, *, minutes=2):
    """Recover a crash-interrupted send WITHOUT retrying it."""
    init_notifications(conn)
    row = conn.execute('SELECT status,updated_at FROM notification_deliveries WHERE case_id=? AND channel=?',
                       (case_id,channel)).fetchone()
    if not row or row[0] != 'Sending':
        raise NotificationError('There is no in-progress notification for this case/channel.')
    try:
        when = datetime.fromisoformat(row[1])
        is_old = when.tzinfo is not None and datetime.now(timezone.utc)-when >= timedelta(minutes=minutes)
    except (ValueError, TypeError):
        is_old = False
    if not is_old:
        raise NotificationError('This send is too recent to be considered interrupted.')
    now = utc_now()
    with conn:
        conn.execute("UPDATE notification_deliveries SET status='Uncertain',last_code='interrupted-send',updated_at=? WHERE case_id=? AND channel=? AND status='Sending'",
                     (now,case_id,channel))
        conn.execute('INSERT INTO notification_audit(case_id,channel,event,detail,recorded_at) VALUES (?,?,?,?,?)',
                     (case_id,channel,'Uncertain','Interrupted; delivery not verified',now))
    return True
