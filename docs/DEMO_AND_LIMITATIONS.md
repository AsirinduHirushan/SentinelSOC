# Demo checklist and limitations

## Suggested recruiter demo (authorized lab only)

1. Show the Wazuh Manager/Indexer and a Windows agent connected in a lab.
2. Open Streamlit, show the operations overview and explain that the score is a **heuristic**.
3. Select a timeline, inspect the evidence grades and explain the uncertainty.
4. Show potential MITRE ATT&CK techniques and analyst guidance; do not claim rule IDs prove an attack.
5. Open a case, record a safe test analyst decision and review the saved audit history.
6. Generate a downloadable handoff report. Only demonstrate outbound email after configuring a destination you control.
7. Run the unit tests in VS Code and explain the difference between tests with mocks and tested live systems.

## Claims to avoid

- "Detects all cyberattacks" or "100% accurate."
- "Process X definitely modified file Y" without matching telemetry.
- "All incidents are malicious" when correlation is contextual.
- "Runs 24/7" before the standalone worker has been installed and validated.
- "Automatically blocks attackers" when actions still require human approval and are not implemented.
