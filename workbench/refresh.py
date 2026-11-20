"""Auto refresh scheduling: no network activity unless requested or due."""
from datetime import datetime


def should_fetch_live(*, force: bool, auto_refresh: bool, key, saved_key,
                      last_attempt: datetime | None, now: datetime, interval=60) -> bool:
    """A data-source change/manual sync fetches immediately; timer is rate limited.

    This function is intentionally independent from Streamlit for easy testing.
    """
    if force or saved_key != key:
        return True
    if not auto_refresh:
        return False
    if last_attempt is None:
        return True
    return (now - last_attempt).total_seconds() >= interval
