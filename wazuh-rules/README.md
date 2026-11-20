# SentinelSOC — Custom Wazuh Detection Rules

Custom Wazuh detection rules developed for the SentinelSOC cybersecurity monitoring and incident investigation lab.

These rules extend Wazuh's existing detection capabilities to identify suspicious authentication and Windows process activity.

## Custom Detection Rules

| Rule ID | Detection | Severity | MITRE ATT&CK |
|---|---|---|---|
| 100120 | Repeated failed logins targeting the same account | Level 10 | T1110 — Brute Force |
| 100121 | User discovery using `whoami` in matching process events | Level 7 | T1033 — System Owner/User Discovery |

## Rule 100120 — Repeated Failed Login Detection

**Objective:** Identify potential password-guessing activity targeting a Windows account.

**Detection logic:**
- Monitors events matching Wazuh rule `60122`.
- Uses `win.eventdata.targetUserName` to correlate authentication failures associated with the same account.
- Configured with a frequency threshold of 4 and a 120-second timeframe.
- Generates a level 10 alert when the correlation conditions are satisfied.

**MITRE ATT&CK:** T1110 — Brute Force.

**Limitations:** Repeated failures can occur during legitimate user activity. The rule requires matching authentication events and should not be treated as proof of an attack.

## Rule 100121 — User Discovery Command Detection

**Objective:** Identify potential system-user discovery activity involving the `whoami` command.

**Detection logic:**
- Requires an event matching Wazuh parent rule `92004`.
- Inspects `win.eventdata.commandLine`.
- Uses a case-insensitive PCRE2 expression to identify `whoami` or `whoami.exe`.
- Generates a level 7 alert when the conditions match.

**MITRE ATT&CK:** T1033 — System Owner/User Discovery.

**Limitations:** The parent-rule requirement restricts detection to events matching rule `92004`; it is not a universal `whoami` detector. Legitimate administration may also generate matching events.

## Rule File

**File:** `sentinelsoc_rules.xml`

The XML contains both custom rules, their match conditions, severity levels and ATT&CK mappings.

## Validation

Validate rule syntax on an authorized Wazuh lab server:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Test detection behavior using representative log events:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Compare the resulting rule IDs, event fields and generated alerts against the expected detection conditions.

XML syntax validation alone does not establish that a rule detects its intended activity.

## Project Integration

Custom detection alerts can be collected through Wazuh and analyzed by the SentinelSOC Analyst Workbench, which supports alert correlation, MITRE ATT&CK enrichment, incident prioritization and analyst-controlled escalation.

## Security and Scope

These rules were developed for a controlled cybersecurity lab. They should be tested and tuned before deployment to other environments.

**Detection does not automatically confirm malicious activity.**