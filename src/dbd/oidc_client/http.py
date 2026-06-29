"""HTTP session used for every provider call.

A single pooled ``requests.Session`` is shared process-wide. Applications that
need custom transport (retries, proxies, mTLS, a system trust store, a test
double) can inject their own session via ``OIDC_CLIENT["session"]`` instead of
monkeypatching.

The catch: the token exchange runs through Authlib's ``OAuth2Session``, a
*distinct* ``requests.Session`` the library must construct itself — it cannot
wrap the injected one. So ``inherit_transport`` copies the injected session's
transport (its mounted adapters plus the TLS/proxy settings) onto that
OAuth2Session. That keeps the single injected session authoritative for *every*
provider call, not just the discovery and JWKS GETs.
"""

import requests
from django.conf import settings

_default_session = requests.Session()

# Transport attributes (besides the mounted adapters) that a custom
# requests.Session may set and that must be carried onto the OAuth2Session. The
# adapters hold the TLS ``SSLContext``; these hold the CA-bundle path / verify
# toggle, the client certificate, the proxy map, and the trust_env switch
# (proxies and netrc from the environment). OAuth concerns — auth and headers —
# are deliberately left untouched so Authlib keeps ownership of them.
_TRANSPORT_ATTRS = ("verify", "cert", "proxies", "trust_env")


def get_session() -> requests.Session:
    """Return the requests session used for provider HTTP calls.

    Returns:
        The session from ``OIDC_CLIENT["session"]`` if configured, otherwise a
        shared process-wide default session.
    """
    config = getattr(settings, "OIDC_CLIENT", None) or {}
    return config.get("session") or _default_session


def inherit_transport(target: requests.Session, source: requests.Session) -> requests.Session:
    """Copy ``source``'s transport policy onto ``target`` and return ``target``.

    Used to make the OAuth2Session that performs the token exchange honor the
    same transport as ``OIDC_CLIENT["session"]`` (the session used for discovery
    and JWKS), so one injected session governs every provider HTTP call.

    Only transport is copied: the mounted adapters (which carry the TLS
    ``SSLContext``) plus ``verify``/``cert``/``proxies``/``trust_env``. Authlib's
    own concerns on ``target`` (auth, headers) are left intact. Adapter instances
    are shared by reference — they are connection-pool holders, safe to share —
    but the adapters *mapping* is copied so a later ``mount`` on one session does
    not mutate the other.

    Args:
        target: The session to configure (e.g. an Authlib ``OAuth2Session``).
        source: The configured session to copy transport from.

    Returns:
        ``target``, for call chaining.
    """
    target.adapters = source.adapters.copy()
    for attr in _TRANSPORT_ATTRS:
        setattr(target, attr, getattr(source, attr))
    return target
