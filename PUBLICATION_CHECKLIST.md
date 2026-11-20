# Pre-publication checklist

- [ ] Verify `.streamlit/secrets.toml`, `.streamlit/certs/`, `local/`, and `reports/` are NOT present.
- [ ] Verify real Wazuh exports, raw JSON and ZIP/RAR archives are NOT present.
- [ ] Review `docs/screenshots/` for personal information before adding pictures.
- [ ] Review custom Wazuh XML rules for hostnames, addresses, credentials and any real sample payloads.
- [ ] Run `python -m unittest discover -s tests -v` in your own environment.
- [ ] Test `Offline sample` and `Synthetic correlation demo`.
- [ ] Confirm Github staged changes with `git diff --cached --name-only` before first commit.
- [ ] Initially publish as a PRIVATE repository; review and then switch to PUBLIC if desired.
- [ ] Document known limitations and don't claim background monitoring or unattended responses are deployed yet.
