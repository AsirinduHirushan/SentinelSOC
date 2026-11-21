"""Read-only Wazuh Indexer ingestion through a LOCAL SSH port forward.

Never expose 9200 publicly; do not log passwords/raw source documents.
"""
from urllib.parse import urlsplit
import ssl
from pathlib import Path
from hashlib import sha256
import hmac
import re
import requests
from requests.adapters import HTTPAdapter

ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
ALERT_INDEX_PATH = "/wazuh-alerts-*/_search"
# Stable even when Streamlit is started from a subdirectory or another shell folder.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Rule descriptions are kept static in the normalized dataset so the raw
# Indexer description cannot accidentally contain a username, host, or path.
SAFE_DESCRIPTIONS = {
    "60122": "Failed Windows authentication",
    "100120": "Repeated Windows login failures (custom rule)",
    "100121": "User discovery process activity (custom rule)",
    "550": "Monitored file checksum changed",
    "92004": "PowerShell launched Windows Command Prompt",
    "92032": "Command Prompt execution matched Wazuh detection",
    "92021": "PowerShell file deletion behavior matched",
    "92031": "System discovery command detected",
    "92066": "Wazuh flagged an unusual administrative process location",
}


class LegacyWazuhCAAdapter(HTTPAdapter):
    """Private-lab compatibility for a CA missing the X.509 KeyUsage extension.

    Still requires the explicitly supplied CA and verifies the peer hostname.
    Only the additional OpenSSL VERIFY_X509_STRICT conformance flag is relaxed.
    This is not a substitute for replacing the noncompliant CA in production.
    """

    def __init__(self, ca_file):
        self.ca_file = Path(ca_file)
        super().__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        context = ssl.create_default_context(cafile=str(self.ca_file))
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        # VERIFY_X509_STRICT is relaxed, but chain, expiration, and hostname
        # validation remain on. Never set CERT_NONE or check_hostname=False.
        pool_kwargs["ssl_context"] = context
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


class LiveSourceError(RuntimeError):
    """User-facing connection problem without raw credential material."""


def _check_local_url(url):
    """Only accept the local TLS endpoint; never send credentials to a remote URL."""
    try:
        parsed = urlsplit(url)
        allowed = (
            parsed.scheme == "https"
            and parsed.hostname in ALLOWED_HOSTS
            and parsed.port == 9200
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        allowed = False
    if not allowed:
        raise LiveSourceError(
            "Use https://127.0.0.1:9200 through an SSH port forward only."
        )
    return url.rstrip("/")


def _token(secret, label, value):
    """Stable non-reversible label for this installation; never export the key."""
    if not secret or not isinstance(value, str) or not value.strip():
        return None
    payload = (label + ":" + value.strip().casefold()).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, "sha256").hexdigest()[:20]


def _principal(event, *, target=False):
    """Normalize Windows DOMAIN\\user consistently across auth and Sysmon."""
    if not isinstance(event, dict):
        return None
    if target:
        name = event.get("targetUserName")
        domain = event.get("targetDomainName")
    else:
        name, domain = event.get("user"), None
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or name in ("-", "SYSTEM", "ANONYMOUS LOGON"):
        return None
    if "\\" in name:
        return name.casefold()
    if isinstance(domain, str) and domain.strip() and domain != "-":
        return (domain.strip() + "\\" + name).casefold()
    # Unknown domain is not safely equated with one that has a known domain.
    return ("unknown-domain\\" + name).casefold()


def _safe_process_name(image):
    if not isinstance(image, str):
        return None
    name = image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    return name if name in {"cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe"} else "other"


def sanitize_hit(hit, correlation_key=None):
    """Project allowlisted metadata; raw usernames, commands and file paths are discarded.

    Enrichment is explicitly opt-in with a local secret. No reversible hashes.
    """
    source = hit.get("_source", {})
    rule = source.get("rule") or {}
    agent = source.get("agent") or {}
    rule_id = rule.get("id")
    timestamp = source.get("timestamp")
    try:
        level = int(rule.get("level"))
    except (ValueError, TypeError):
        return None
    if not timestamp or rule_id is None or not (0 <= level <= 15):
        return None
    groups = rule.get("groups", [])
    if not isinstance(groups, list):
        groups = []
    agent_id = str(agent.get("id") or "unknown")[:12]
    if not re.fullmatch(r"[0-9]{1,12}", agent_id):
        agent_id = "unknown"
    rid = str(rule_id)
    if not re.fullmatch(r"[0-9]{1,7}", rid):
        return None
    win = (source.get("data") or {}).get("win") or {}
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or {}
    syscheck = source.get("syscheck") or {}
    win_id = str(system.get("eventID") or "")
    channel = str(system.get("channel") or "")
    if win_id == "4625" or str(rule_id) in ("60122", "100120"):
        kind = "Authentication"
        principal = _principal(eventdata, target=True)
    elif syscheck and (syscheck.get("path") or syscheck.get("event")) or str(rule_id) == "550":
        kind = "File Integrity"
        # Whodata is optional; never assume a file change was caused by a nearby process.
        audit = syscheck.get("audit") or {}
        user = audit.get("user") or {}
        principal = _principal({"user": user.get("name")}) if isinstance(user, dict) else None
    elif ("sysmon" in channel.casefold() and win_id == "1") or str(rule_id) in ("100121", "92004", "92032"):
        kind = "Process"
        principal = _principal(eventdata)
    else:
        kind = None
        principal = None
    # A source ID is opaque, but never echo index names/IDs back into portfolio output.
    idx_id = str(hit.get("_index") or "") + ":" + str(hit.get("_id") or "")
    ref = sha256(idx_id.encode()).hexdigest()[:12] if hit.get("_id") else None
    event_record = str(system.get("eventRecordID") or "")
    event_fingerprint = _token(correlation_key, "win-event", agent_id + ":" + channel + ":" + event_record) if event_record and channel else None
    command_image = eventdata.get("image") if kind == "Process" else None
    return {
        "timestamp": str(timestamp),
        "rule_id": rid,
        "level": level,
        "description": SAFE_DESCRIPTIONS.get(rid, f"Wazuh rule {rid} alert"),
        "groups": [g for g in groups if isinstance(g, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", g)][:30],
        "agent": "endpoint-" + agent_id,
        "source_kind": kind,
        "account_token": ("acct_" + _token(correlation_key, "account", principal)) if (principal and correlation_key) else None,
        "process_token": _token(correlation_key, "process-guid", str(eventdata.get("processGuid") or "")) if kind == "Process" else None,
        "parent_process_token": _token(correlation_key, "process-guid", str(eventdata.get("parentProcessGuid") or "")) if kind == "Process" else None,
        "file_token": _token(correlation_key, "file", str(syscheck.get("path") or "")) if kind == "File Integrity" else None,
        "source_event_token": event_fingerprint,
        "event_ref": ref,
        "file_action": str(syscheck.get("event") or "").lower() if kind == "File Integrity" else None,
        "process_name": _safe_process_name(command_image) if kind == "Process" else None,
    }


def _resolve_ca_bundle(ca_bundle):
    """Resolve CA paths relative to this project, not the shell's current directory.

    This prevents the local SSH tunnel from failing when Streamlit is started
    outside the project root. Only a readable PEM certificate bundle is allowed.
    """
    if ca_bundle is None or not str(ca_bundle).strip():
        return None
    candidate = Path(str(ca_bundle).strip()).expanduser()
    path = (candidate if candidate.is_absolute() else PROJECT_ROOT / candidate).resolve()
    try:
        if not path.is_file():
            raise FileNotFoundError("CA bundle file is missing")
        with path.open("rb") as cert_file:
            if b"-----BEGIN CERTIFICATE-----" not in cert_file.read(8192):
                raise ValueError("Not a PEM certificate bundle")
    except (OSError, ValueError) as exc:
        raise LiveSourceError(
            "Cannot load the local Wazuh CA certificate. Check that ca_bundle "
            "points to a readable PEM file; relative paths start from the "
            "SentinelSOC project root."
        ) from exc
    return str(path)


def fetch_recent_alerts(url, username, password, *, verify_tls=True, ca_bundle=None,
                        hours=24, limit=500, requester=requests.post, legacy_ca_compat=False,
                        correlation_key=None):
    """Fetch recent alerts with limits, TLS controls, and a read-only search API.

    No credentials are ever written to disk by this module.
    """
    base = _check_local_url(url)
    if correlation_key is not None and (not isinstance(correlation_key, str) or len(correlation_key) < 32):
        raise LiveSourceError("Correlation key must be at least 32 characters in private Streamlit secrets.")
    if not username or not password:
        raise LiveSourceError("Set an indexer username and password in local Streamlit secrets.")
    if not isinstance(hours, int) or not 1 <= hours <= 168:
        raise ValueError("hours must be 1..168")
    if not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("limit must be 1..1000")
    resolved_ca = _resolve_ca_bundle(ca_bundle) if verify_tls else None
    if legacy_ca_compat and (not verify_tls or not resolved_ca):
        raise LiveSourceError("Legacy lab CA compatibility requires verify_tls=true and an explicit ca_bundle.")
    verify = resolved_ca if resolved_ca else bool(verify_tls)
    body = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
        "_source": ["timestamp", "rule.id", "rule.level", "rule.description",
                    "rule.groups", "agent.id", "data.win.system.eventID",
                    "data.win.system.channel", "data.win.system.eventRecordID",
                    "data.win.eventdata.targetUserName", "data.win.eventdata.targetDomainName",
                    "data.win.eventdata.user", "data.win.eventdata.processGuid",
                    "data.win.eventdata.parentProcessGuid", "data.win.eventdata.image",
                    "syscheck.path", "syscheck.event", "syscheck.audit.user.name"],
        "track_total_hits": False,
    }
    try:
        if legacy_ca_compat and requester is requests.post:
            with requests.Session() as session:
                # Mounted only for the allowlisted localhost Indexer endpoint.
                session.mount(base + "/", LegacyWazuhCAAdapter(resolved_ca))
                response = session.post(base + ALERT_INDEX_PATH, json=body,
                                        auth=(username, password), verify=verify,
                                        timeout=(4, 18), allow_redirects=False)
        else:
            response = requester(base + ALERT_INDEX_PATH, json=body,
                                 auth=(username, password), verify=verify,
                                 timeout=(4, 18), allow_redirects=False)
    except requests.exceptions.SSLError as exc:
        raise LiveSourceError(
            "Wazuh TLS verification failed. Check that the local CA bundle trusts "
            "the Indexer certificate and that its hostname is valid."
        ) from exc
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        raise LiveSourceError(
            "Cannot reach Wazuh through the local SSH tunnel at 127.0.0.1:9200. "
            "Check that the Wazuh VM and the SSH port forward are still running."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise LiveSourceError(
            "The Wazuh Indexer HTTPS request failed. Check the tunnel and Indexer service."
        ) from exc
    except OSError as exc:
        raise LiveSourceError(
            "A local file or SSL initialization error occurred. Check CA bundle "
            "read permissions and the SSH tunnel."
        ) from exc
    if response.status_code == 401:
        raise LiveSourceError("Indexer authentication failed (401). Check local credentials.")
    if response.status_code == 403:
        raise LiveSourceError("Indexer access denied (403). Use a read-only account with alerts search access.")
    if response.status_code >= 300:
        raise LiveSourceError(f"Indexer search failed (HTTP {response.status_code}).")
    try:
        hits = response.json()["hits"]["hits"]
        if not isinstance(hits, list):
            raise TypeError("Invalid hits response")
    except (KeyError, ValueError, TypeError) as exc:
        raise LiveSourceError("Indexer returned an unexpected response format.") from exc
    clean = [row for hit in hits if (row := sanitize_hit(hit, correlation_key=correlation_key)) is not None]
    return clean
