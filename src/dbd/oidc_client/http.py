"""HTTP session used for every provider call.

A single pooled ``requests.Session`` is shared process-wide. Applications that
need custom transport (retries, proxies, mTLS, a test double) can inject their
own session via ``OIDC_CLIENT["session"]`` instead of monkeypatching.
"""

import requests
from django.conf import settings

_default_session = requests.Session()


def get_session() -> requests.Session:
    """Return the requests session used for provider HTTP calls.

    Returns:
        The session from ``OIDC_CLIENT["session"]`` if configured, otherwise a
        shared process-wide default session.
    """
    config = getattr(settings, "OIDC_CLIENT", None) or {}
    return config.get("session") or _default_session
