"""Conservative rule-based MITRE ATT&CK suggestions for sanitized Wazuh alerts.

Suggestions are ATT&CK technique *hypotheses*, not verified adversary behavior.
Only project-owned, predefined Wazuh rule IDs are recognized; no raw log strings,
command-lines, user names, file paths, or external APIs are needed.
"""
from collections import defaultdict

# Curated mappings, checked against MITRE ATT&CK Enterprise documentation.
# Deliberately do NOT map generic Windows 4625 events or FIM modifications.
# (technique_id, technique, tactic, reason, next_action)
TECHNIQUES = {
    'T1110': ('Brute Force', 'Credential Access',
        'Repeated authentication-failure detection may be consistent with brute-force attempts.',
        'Review failure counts, affected accounts, source context, and any later successes.'),
    'T1033': ('System Owner/User Discovery', 'Discovery',
        'User discovery execution may be consistent with identity enumeration.',
        'Check the authorized purpose and execution context of the discovery process.'),
    'T1082': ('System Information Discovery', 'Discovery',
        'A system discovery command was flagged by Wazuh.',
        'Check what system information was queried and whether the activity was expected.'),
    'T1059.001': ('Command and Scripting Interpreter: PowerShell', 'Execution',
        'PowerShell execution or behavior was detected; PowerShell is commonly legitimate.',
        'Review the approved script, parent process, user context, and authorized purpose.'),
    'T1059.003': ('Command and Scripting Interpreter: Windows Command Shell', 'Execution',
        'Command Prompt execution or invocation was detected; cmd.exe is commonly legitimate.',
        'Review parent-child process lineage and whether the shell execution was expected.'),
    'T1070.004': ('Indicator Removal: File Deletion', 'Defense Evasion',
        'A rule matched potential file-deletion behavior; actual malicious deletion is unconfirmed.',
        'Determine whether a file was deleted and whether it was expected maintenance.'),
}

# Map only rules whose safe, project-defined descriptions imply the observed behavior.
RULE_TECHNIQUES = {
    '100120': ('T1110',),  # repeated Windows failures (custom rule)
    '100121': ('T1033',),  # user discovery process activity
    '92031': ('T1082',),   # system discovery command
    '92004': ('T1059.001', 'T1059.003'),  # PowerShell launched cmd.exe
    '92032': ('T1059.003',),  # cmd.exe execution
    '92021': ('T1059.001', 'T1070.004'),  # PowerShell file deletion behavior matched
}


def technique_url(technique_id):
    """Build only official MITRE URLs from a private, allowlisted identifier."""
    if technique_id not in TECHNIQUES:
        raise ValueError('Unknown MITRE technique')
    return 'https://attack.mitre.org/techniques/' + technique_id.replace('.', '/') + '/'


def map_alerts(alerts):
    """Return stable, deduplicated review hints for normalized alerts.

    Multiple Wazuh rule alerts for one underlying Windows event are treated as
    one independent source *per technique*, not as additional independent proof.
    """
    sources = defaultdict(set)
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        rule_id = str(alert.get('rule_id', ''))
        for technique_id in RULE_TECHNIQUES.get(rule_id, ()):
            # A source token exists only when the trusted sanitizer extracted one.
            # Otherwise each normalized alert is counted separately (not called independent).
            src = alert.get('source_event_token') or alert.get('alert_id')
            if src:
                sources[technique_id].add(str(src))
            else:
                # Sparse records are not counted as independent evidence.
                sources[technique_id].add('unidentified-source')
    result = []
    for technique_id in sorted(sources):
        name, tactic, reason, action = TECHNIQUES[technique_id]
        result.append({
            'technique_id': technique_id, 'technique': name, 'tactic': tactic,
            'reason': reason, 'next_action': action,
            'source_count': len(sources[technique_id]),
            'url': technique_url(technique_id),
            'confidence': 'Possible behavior mapping; not an attack determination',
        })
    return result


def attack_report_section(alerts):
    """Markdown appendix suitable for existing investigation reports."""
    mapped = map_alerts(alerts)
    out = ['\n## Potential MITRE ATT&CK techniques (rule-based)', '',
           'These are investigation hypotheses, not proof of attacker activity or technique execution.', '']
    if not mapped:
        out.append('No mapping from the curated rules. This does not mean activity is benign.')
    for row in mapped:
        out.extend([f"### {row['technique_id']} — {row['technique']}", '',
                    f"- Tactic: {row['tactic']}",
                    f"- Supporting distinct source identifiers (where identifiable): {row['source_count']}",
                    f"- Why suggested: {row['reason']}",
                    f"- Analyst next step: {row['next_action']}",
                    f"- MITRE ATT&CK: {row['url']}", ''])
    return '\n'.join(out) + '\n'
