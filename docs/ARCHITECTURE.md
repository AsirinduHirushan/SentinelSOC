# Architecture

SentinelSOC is a local analyst workbench, **not a replacement for Wazuh**.

```text
[Windows lab host: Sysmon / Security / FIM]
                   |
               [Wazuh Agent]
                   |
      [Wazuh Manager + Indexer]
                   |
        [SSH tunnel on localhost]
                   |
[read-only search + privacy projection]
                   |
           [Streamlit UI]
            /     |       \
   correlation  scoring  MITRE suggestions
            \     |       /
      [Investigation and review]
                   |
 [SQLite: analyst decisions and audit]
                   |
     [Optional approved handoff]
```

- `workbench/live.py`: restricted Wazuh Indexer reader and sanitizer.
- `workbench/engine.py`: normalization, case grouping, score explanations.
- `workbench/correlation.py`: evidence timelines and relationship strengths.
- `workbench/attack_mapping.py`: possible MITRE ATT&CK mappings, not conclusions.
- `workbench/escalation.py` and `workbench/response.py`: local escalation policy and analyst recommendations.
- `workbench/notifications.py`: approved delivery, deduplication and audit.
- `workbench/state.py`: persisted analyst review history.

**Trust boundaries:** credentials and CA certificates stay local. Real raw alerts and SQLite history are excluded from source control. The UI is configured for localhost use.
