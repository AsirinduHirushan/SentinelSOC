# Local setup and publication safety

## Prerequisites

- Python supported by the selected dependency versions
- Wazuh VM and Windows Sysmon/agent **only for optional live mode**
- VS Code + Git

## Offline test

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m streamlit run app.py
```

The offline mode reads **synthetic** data from `data/` and does not need Wazuh.

## Live mode (authorized lab only)

From a separate Windows terminal (adjust SSH user and VM IP yourself):

```powershell
ssh -N -L 127.0.0.1:9200:127.0.0.1:9200 YOUR_SSH_USER@YOUR_WAZUH_SERVER_IP
```

Create a local private config (`.streamlit/secrets.toml`) based on the example file. Use a read-only Indexer account and a trusted CA bundle. Never expose the Indexer port on a public interface. Keep this tunnel terminal open during manual live sessions.

> **Do not commit** `.streamlit/secrets.toml`, `.streamlit/certs/`, `local/`, `reports/`, real JSONL/JSON exports, private rules with identifying information, SSH keys, or app-passwords. Old Git commits can retain removed secrets, so review **before your first commit**.

## Verification before GitHub upload

```powershell
git status --short
git add -A
git diff --cached --name-only
git diff --cached --check
```

Review every staged file. Ensure no real logs, local databases, certificates, passwords or unredacted screenshots are staged. Use `git restore --staged <path>` to remove anything unexpected from staging.

## Existing limitations

- No unattended 24/7 service in this version.
- Alert correlation is evidence-based heuristic grouping; not proof of a single attack.
- MITRE technique suggestions may be broader than the actual behavior; manual verification required.
- Notifications are initiated manually after analyst approval, not triggered in the background.
- Production hardening, multi-user authorization, retention controls and detection coverage measurement remain future work.
