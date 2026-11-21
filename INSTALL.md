# SentinelSOC Wazuh Live Connection Repair

This archive fixes the user-supplied `workbench/live.py` while preserving its public API,
allowlisted Wazuh alert projection, local-only endpoint requirement, and TLS verification.

## Changes

- Corrected the syntax error in the `try` / `except` blocks.
- Categorized TLS certificate failures separately from SSH tunnel connection and timeout errors.
- Made OS/file errors generic rather than automatically blaming the CA certificate.
- Standardized the local endpoint guard for malformed URLs.
- Added eight standalone regression tests. No test sends a network request.

**This is an error-handling repair, not an SSH tunnel daemon.** Your running VM and
SSH port forward must still be available for live queries. This package does not
alter certificates, `secrets.toml`, or the local SQLite database.

## Install (VS Code PowerShell)

Stop the Streamlit process with Ctrl+C, then run:

```powershell
cd "C:\Users\LOQ\Desktop\SOC PROJECT GIT\SentinelSOC"
Copy-Item .\workbench\live.py .\workbench\live.py.before-connection-repair.bak -Force
Expand-Archive "$env:USERPROFILE\Downloads\SentinelSOC_Live_Connection_Fix.zip" -DestinationPath (Get-Location).Path -Force
.\.venv\Scripts\python.exe -m py_compile .\workbench\live.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

If all tests pass, check CA and tunnel:

```powershell
Test-Path .\.streamlit\certs\wazuh-root-ca.pem
Test-NetConnection 127.0.0.1 -Port 9200
```

Both should be positive. If the tunnel is down, start it in a **separate** terminal:

```powershell
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -L 127.0.0.1:9200:127.0.0.1:9200 wazuh-user@192.168.1.101
```

The terminal remains occupied while forwarding traffic. Do not expose port 9200 on
an external interface. To restart Streamlit:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Click **Live via SSH tunnel > Sync alerts now**.

Expected failure categories:

- `Cannot load the local Wazuh CA certificate`: configured CA path missing/invalid/unreadable.
- `Cannot reach Wazuh through the local SSH tunnel`: SSH forward, VM, or network is unavailable.
- `Wazuh TLS verification failed`: the peer certificate or hostname cannot be verified against your CA.
- `401`/`403`: credential or authorization issue.

After local testing, review changes and commit only the source/tests:

```powershell
git add workbench/live.py tests/test_live_connection_errors.py
git diff --cached --check
git commit -m "Fix Wazuh TLS and SSH tunnel error handling"
git push
```

Backups (`*.bak`) should stay local and should not be committed.
