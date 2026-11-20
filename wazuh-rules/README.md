# Custom Wazuh rules

Place your **reviewed** custom rules here after copying them from your separate working files.

Before publishing XML:

1. Remove private hostnames, usernames, internal IP addresses, domains, paths and tokens, if any.
2. Check that no secrets, credentials, or raw alert payloads are included.
3. Keep rule IDs, levels, groups, descriptions and match logic if safe.
4. Document the rule's intended detection, test input, expected results and false-positive limitations.
5. Validate syntax in your authorized Wazuh lab; do not claim unverified rules are production detections.

Do not publish server secrets, certificate material, or the complete `ossec.conf` from a private installation.
