"""Evidence-led, non-causal multi-signal investigation timelines.

A chain is a *candidate for analyst review*, never a validated incident.
Strong links only use equal private HMAC tokens (principal/process/file).
Coincidence on an endpoint within 15 minutes is always labeled temporal-only.
"""
from collections import Counter, defaultdict
from datetime import datetime
from hashlib import sha256

WINDOW_SECONDS = 15 * 60
SIGNAL_KINDS = {"Authentication", "Process", "File Integrity"}


def _when(event):
    return datetime.fromisoformat(event['timestamp'])


def _kind(event):
    category = event.get('source_kind')
    if category in SIGNAL_KINDS:
        return category
    existing = event.get('category')
    if existing == 'Authentication':
        return 'Authentication'
    if existing == 'Process Discovery':
        return 'Process'
    if existing == 'File Integrity':
        return 'File Integrity'
    return None


def _link(before, after):
    """Return explicit evidence type; never infer that temporal overlap is causation."""
    if before.get('agent') != after.get('agent'):
        return None
    if abs((_when(after) - _when(before)).total_seconds()) > WINDOW_SECONDS:
        return None
    a_guid, a_parent = before.get('process_token'), before.get('parent_process_token')
    b_guid, b_parent = after.get('process_token'), after.get('parent_process_token')
    if (a_guid and a_guid in (b_guid, b_parent)) or (b_guid and b_guid == a_parent):
        return 'Sysmon process GUID'
    file_ref = before.get('file_token')
    if file_ref and file_ref == after.get('file_token'):
        return 'same-file token'
    account = before.get('account_token')
    if account and account == after.get('account_token'):
        return 'same-account token'
    return 'same endpoint / time only'


# Strength of the *record relationship*, not proof of an attack.
LINK_RANK = {'Sysmon process GUID': ('high', 3), 'same-file token': ('medium', 2),
             'same-account token': ('medium', 1), 'same endpoint / time only': ('context', 0)}


def build_timelines(alerts, window_seconds=WINDOW_SECONDS):
    """Create strictly time-bounded, same-endpoint, multi-type review candidates.

    Requires at least two different signal types. Separates events by a hard
    window measured from the first event (not a chain of sliding gaps).
    """
    by_endpoint = defaultdict(list)
    for a in alerts:
        if _kind(a) and a.get('agent'):
            by_endpoint[a['agent']].append(a)
    output = []
    for agent, events in by_endpoint.items():
        events.sort(key=lambda e: (e['timestamp'], e['alert_id']))
        batch = []
        for a in events:
            if batch and (_when(a) - _when(batch[0])).total_seconds() > window_seconds:
                item = _make_timeline(agent, batch)
                if item:
                    output.append(item)
                batch = []
            batch.append(a)
        if batch:
            item = _make_timeline(agent, batch)
            if item:
                output.append(item)
    return sorted(output, key=lambda c: (c['first_seen'], c['timeline_id']), reverse=True)


def _make_timeline(agent, events):
    kinds = {_kind(e) for e in events}
    if len(kinds) < 2:
        return None
    # Repeated detections for one underlying Windows event are not separate source events.
    source_keys = {a.get('source_event_token') or a['alert_id'] for a in events}
    links = []
    for idx, current in enumerate(events[1:], 1):
        options = []
        for prev in events[:idx]:
            # Repeated Wazuh rule alerts for one source event are NOT distinct evidence.
            if (prev.get('source_event_token') and
                    prev.get('source_event_token') == current.get('source_event_token')):
                continue
            relationship = _link(prev, current)
            if not relationship:
                continue
            # A repeated login from the same account isn't evidence of a multi-signal chain.
            if (_kind(prev) == _kind(current) and
                    relationship not in ('Sysmon process GUID', 'same-file token')):
                continue
            options.append((relationship, prev))
        if not options:
            continue
        # Highest evidential relationship first; ties favor nearest prior event.
        relationship, prev = max(options, key=lambda item: LINK_RANK[item[0]][1])
        links.append({'from_ref': prev.get('event_ref') or prev['alert_id'],
                      'to_ref': current.get('event_ref') or current['alert_id'],
                      'evidence': relationship, 'strength': LINK_RANK[relationship][0]})
    counts = Counter(link['strength'] for link in links)
    high_links = counts['high']
    medium_links = counts['medium']
    context_links = counts['context']
    verified = high_links + medium_links  # compatibility with existing Workbench UI.
    evidence_level = 'high' if high_links else 'medium' if medium_links else 'context'
    if high_links:
        relationship = 'Process GUID relationship present'
        limitation = ('A matching Sysmon process/parent GUID supports process lineage, '
                      'not a confirmed attack or proof other nearby events are related.')
    elif medium_links:
        relationship = 'Shared account/file context present'
        limitation = ('A matching pseudonymous account or file supports shared context, '
                      'but does not prove a single login session or what caused a file change. '
                      'Nearby events may be unrelated.')
    else:
        relationship = 'Endpoint/time context only'
        limitation = ('Only endpoint and timing overlap is established. '
                      'Events may be unrelated; no shared entity relationship is established.')
    seed = f"{agent}|{events[0].get('event_ref', events[0]['alert_id'])}|multisignal"
    return {
        'timeline_id': 'TIM-' + sha256(seed.encode()).hexdigest()[:8].upper(),
        'agent': agent,
        'first_seen': events[0]['timestamp'],
        'last_seen': events[-1]['timestamp'],
        'signal_types': sorted(kinds),
        'alerts': events,
        'alert_count': len(events),
        'distinct_source_events': len(source_keys),
        'links': links,
        'verified_links': verified,
        'high_links': high_links,
        'medium_links': medium_links,
        'context_links': context_links,
        'evidence_level': evidence_level,
        'relationship': relationship,
        'limitation': limitation,
    }


def timeline_report(timeline, status="New", notes=""):
    def safe(s):
        return str(s).replace('|', '\\|').replace('<', '&lt;').replace('>', '&gt;').replace('\n', ' ').replace('\r', ' ')
    lines = [f"# SentinelSOC Timeline {timeline['timeline_id']}", '',
             '**Classification:** Investigation candidate — NOT a confirmed incident',
             f'**Analyst review status:** {safe(status)}',
             f"**Endpoint:** {safe(timeline['agent'])}",
             f"**Window:** {timeline['first_seen']} – {timeline['last_seen']} (UTC)",
             f"**Signal types:** {', '.join(timeline['signal_types'])}",
             f"**Alerts / distinct source events:** {timeline['alert_count']} / {timeline['distinct_source_events']}",
             f"**Record relationship strength:** {timeline['evidence_level'].upper()} (not incident severity)",
             f"**Record links:** high={timeline['high_links']}, medium={timeline['medium_links']}, context={timeline['context_links']}",
             f"**Entity-linked relationships:** {timeline['verified_links']}", '',
             '## Chronological alert evidence', '',
             '| UTC | Type | Rule | Source ref | Level | Description |',
             '|---|---|---|---|---:|---|']
    for a in timeline['alerts']:
        lines.append(f"| {a['timestamp']} | {_kind(a)} | {a['rule_id']} | "
                     f"{safe(a.get('event_ref','n/a'))} | {a['level']} | {safe(a['description'])} |")
    lines += ['', '## Relationship evidence', '']
    if not timeline['links']:
        lines.append('- No links between different signal types could be established.')
    for link in timeline['links']:
        lines.append(f"- {safe(link['from_ref'])} → {safe(link['to_ref'])}: {safe(link['evidence'])}")
    lines += ['', '## Analyst findings / next actions', '', safe(notes).strip() or 'Not yet reviewed.',
              '', '## What cannot be concluded', '', timeline['limitation'],
              '', '- Alerts are a time-limited, incomplete Indexer sample; absence of events is not proof of absence.',
              '- Usernames, paths and command lines are not exported or displayed.',
              '- Manual investigation is necessary before classifying an incident.', '']
    return '\n'.join(lines)
