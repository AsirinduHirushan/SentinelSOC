# What was deliberately omitted from the uploaded workbench RAR

The GitHub-ready package was created separately. The original local workbench was not changed.

## Excluded private or local state

- `.streamlit/secrets.toml` (authentication and pseudonymization settings)
- `.streamlit/certs/wazuh-root-ca.pem` (local CA material)
- `local/triage.sqlite3` (saved analyst reviews and escalation/notification state)
- `reports/CASE-*.md` and `reports/cases.json` (generated local case reports)
- All `__pycache__/` folders and `.pyc` files

## Excluded previous installers, patch docs and backups

- `app.py.backup`, `app.py.before-attack-mapping`, `app.py.before-evidence`
- Timestamped `app.py.before-notifications-*.bak` and `app.py.before-response-*.bak`
- `workbench/live.py.backup`, `workbench/correlation.py.before-evidence`
- `tests/test_correlation.py.before-evidence`
- Previous `install_notifications_upgrade.py` and `install_response_upgrade.py` scripts
- Old `APPLY_PATCH.md`, `APPLY_CORRELATION_PATCH.md`, `PATCH_README.md`, `INSTALL_CA_FIX.md`, `INSTALL.md`, `ADVANCED_CORRELATION_README.md`

## Replaced / updated

- `README.md` has been rewritten to reflect functionality currently present.
- `.gitignore` has been strengthened.
- `data/sentinelsoc-alerts.jsonl` was replaced with **fully synthetic** 30-alert sample data; do not publish the original lab export without a separate privacy review.
- `.streamlit/secrets.toml.example` was made generic and contains only placeholders.
- `requirements.txt` includes the libraries directly imported by the app.

## Not yet part of the package

- Your separately stored screenshots and custom Wazuh rules. Add them after checking for private information.
- The proposed standalone continuous-monitoring upgrade (not yet installed in the uploaded RAR).
