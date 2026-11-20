"""Local, conservative response suggestions for sanitized SentinelSOC cases.

No network requests, email, endpoint actions, privileged commands or automation.
The risk score is a prioritization heuristic, NOT likelihood of compromise.
"""
from workbench.attack_mapping import map_alerts


def _unique_source_count(alerts):
    """Only count independently identifiable source events, not alert rows."""
    tokens = set()
    for alert in alerts:
        token = alert.get('source_event_token') or alert.get('event_ref')
        if isinstance(token, str) and token:
            tokens.add(token)
    return len(tokens)


def response_plan(case):
    """Return explainable recommendations for a CASE, without claiming an attack."""
    alerts = case.get('alerts', [])
    score = max(0, min(100, int(case.get('score', 0))))
    top_level = max((int(a.get('level', 0)) for a in alerts), default=0)
    sources = _unique_source_count(alerts)
    category = str(case.get('category', 'Other'))
    techniques = {row['technique_id'] for row in map_alerts(alerts)}

    # A single genuinely critical Wazuh rule can warrant human triage, even
    # without a process token. We do not call this a confirmed compromise.
    if top_level >= 14 or (score >= 85 and sources >= 2):
        priority = 'P1'
    elif top_level >= 12 or (score >= 65 and sources >= 2):
        priority = 'P2'
    else:
        priority = None

    reasons = [f'Wazuh max rule level {top_level}',
               f'heuristic priority score {score}/100',
               f'{sources} identifiable source event(s)']
    if priority and top_level < 12:
        reasons.append('score threshold plus multiple identifiable source events')
    elif priority and top_level >= 12:
        reasons.append('high-severity Wazuh alert')
    else:
        reasons.append('below automatic queue criteria')

    actions = [
        {'phase': 'Validate', 'action': 'Confirm the events reflect real endpoint activity, not a known lab test, maintenance or duplicate alerts.', 'approval': False},
        {'phase': 'Preserve evidence', 'action': 'Record the alert identifiers, timestamps, rule IDs and relevant authorized logs before making changes.', 'approval': False},
    ]
    if category == 'Authentication' or 'T1110' in techniques:
        actions.append({'phase': 'Investigate', 'action': 'Check the verified account identity, login-failure pattern, source context and any successful logons.', 'approval': False})
        actions.append({'phase': 'Contain (if confirmed)', 'action': 'Request authorization before resetting credentials, revoking sessions or restricting account access.', 'approval': True})
    elif category in ('Process Discovery', 'Process') or techniques.intersection({'T1059.001', 'T1059.003', 'T1033', 'T1082', 'T1070.004'}):
        actions.append({'phase': 'Investigate', 'action': 'Check process ancestry, signer, execution context and whether scripts/commands were approved.', 'approval': False})
        actions.append({'phase': 'Contain (if confirmed)', 'action': 'Request approval before stopping a process or isolating an endpoint. Consider business impact.', 'approval': True})
    elif category == 'File Integrity':
        actions.append({'phase': 'Investigate', 'action': 'Verify the file change against expected deployments and assess integrity using approved evidence.', 'approval': False})
        actions.append({'phase': 'Contain (if confirmed)', 'action': 'Get approval before restoring files, reverting changes or restricting endpoint access.', 'approval': True})
    else:
        actions.append({'phase': 'Investigate', 'action': 'Examine the triggered rule, relevant sanitized evidence and whether the event was expected.', 'approval': False})
        actions.append({'phase': 'Contain (if confirmed)', 'action': 'Seek approval for any containment, account changes or endpoint actions.', 'approval': True})
    actions.append({'phase': 'Escalate', 'action': 'If impact or malicious activity is substantiated, notify the designated response owner through your approved process.', 'approval': True})
    actions.append({'phase': 'Close / learn', 'action': 'Document the analyst verdict, supporting evidence, limitations and follow-up actions.', 'approval': False})
    return {
        'priority': priority,
        'queued_recommended': priority is not None,
        'reason': '; '.join(reasons) + '. This is a review recommendation, not proof of compromise.',
        'score': score,
        'max_rule_level': top_level,
        'distinct_sources': sources,
        'actions': actions,
        'safety_note': 'Human approval required for disruptive containment. SentinelSOC does not execute response commands or send notifications.',
    }


def response_report_section(case):
    """Privacy-preserving Markdown appendix; no raw logs or credentials."""
    p = response_plan(case)
    rows = ['\n## Suggested incident response and escalation', '',
            f"- Auto-triage: {p['priority'] or 'Routine review (not queued)'}",
            f"- Reason: {p['reason']}",
            f"- Safety: {p['safety_note']}", '', '### Human review checklist', '']
    for action in p['actions']:
        approval = ' (human approval required)' if action['approval'] else ''
        rows.append(f"- **{action['phase']}**: {action['action']}{approval}")
    return '\n'.join(rows) + '\n'
