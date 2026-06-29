"""The injected ``OIDC_CLIENT["session"]`` must govern the token exchange too.

The token exchange runs through Authlib's ``OAuth2Session`` — a separate object
from the ``requests.Session`` used for discovery/JWKS. ``inherit_transport``
bridges them by copying transport (mounted adapters + TLS/proxy settings) across.

Two groups of tests:

* behavior — the bridge copies what it should, by identity, without aliasing;
* boundary — the third-party interface the bridge stands on. These pin that
  Authlib's ``OAuth2Session`` is still a ``requests.Session`` and that the
  transport surface we read/write still exists, so a future Authlib/requests
  upgrade that moves the ground trips a clear assertion here instead of
  surfacing as a baffling TLS verification failure in production.
"""

from collections.abc import MutableMapping

import requests
from authlib.integrations.requests_client import OAuth2Session
from requests.adapters import HTTPAdapter

from dbd.oidc_client.client import OpenIDConfiguration, OpenIDConnectAuthorizationProvider
from dbd.oidc_client.http import _TRANSPORT_ATTRS, inherit_transport


def _provider():
    return OpenIDConnectAuthorizationProvider(
        redirect_uri="https://app.example/callback/",
        client_id="client",
        client_secret="secret",
        open_id_configuration=OpenIDConfiguration(
            authorization_endpoint="https://idp.example/authorize",
            token_endpoint="https://idp.example/token",
        ),
    )


# --- behavior: the token-exchange session inherits the injected transport ---


def test_inherit_transport_copies_adapters_and_settings():
    sentinel = HTTPAdapter()
    source = requests.Session()
    source.mount("https://", sentinel)
    source.verify = "/etc/ssl/custom-ca.pem"
    source.cert = ("/client.pem", "/client.key")
    source.proxies = {"https": "http://proxy.example:8080"}
    source.trust_env = False

    target = inherit_transport(requests.Session(), source)

    # The adapter that will serve POST /token is the injected one, by identity.
    assert target.get_adapter("https://idp.example/token") is sentinel
    assert target.verify == "/etc/ssl/custom-ca.pem"
    assert target.cert == ("/client.pem", "/client.key")
    assert target.proxies == {"https": "http://proxy.example:8080"}
    assert target.trust_env is False


def test_inherit_transport_copies_the_mapping_not_the_reference():
    source = requests.Session()
    target = inherit_transport(requests.Session(), source)

    # Mounting on one session afterwards must not bleed into the other.
    source.mount("https://only-source/", HTTPAdapter())
    assert "https://only-source/" not in target.adapters


def test_provider_token_session_inherits_injected_adapter(settings):
    sentinel = HTTPAdapter()
    injected = requests.Session()
    injected.mount("https://", sentinel)
    settings.OIDC_CLIENT = {**settings.OIDC_CLIENT, "session": injected}

    session = _provider()._session("https://app.example/callback/")

    assert session.get_adapter("https://idp.example/token") is sentinel


# --- boundary: the third-party interface the bridge depends on ---


def test_oauth2session_is_a_requests_session():
    # inherit_transport() treats the token-exchange object as a requests.Session.
    # If Authlib stops subclassing it, copying transport silently no-ops and the
    # token POST falls back to requests' default TLS. Fail loudly here instead.
    assert issubclass(OAuth2Session, requests.Session)


def test_requests_session_exposes_the_transport_surface_we_copy():
    # inherit_transport() reads/writes .adapters + _TRANSPORT_ATTRS. Pin them so a
    # requests upgrade that renames or drops one trips here, not in production TLS.
    session = requests.Session()
    assert isinstance(session.adapters, MutableMapping)
    assert callable(session.mount) and callable(session.get_adapter)
    for attr in _TRANSPORT_ATTRS:
        assert hasattr(session, attr), f"requests.Session no longer exposes {attr!r}"


def test_oauth2session_exposes_the_transport_surface_we_write():
    # The actual token-exchange object must accept everything we copy onto it.
    session = OAuth2Session(client_id="x")
    assert isinstance(session.adapters, MutableMapping)
    for attr in _TRANSPORT_ATTRS:
        assert hasattr(session, attr), f"OAuth2Session no longer exposes {attr!r}"


def test_get_adapter_resolves_by_url_prefix():
    # inherit_transport relies on get_adapter() returning the adapter mounted for a
    # scheme. Lock requests' prefix-resolution behavior.
    session = requests.Session()
    sentinel = HTTPAdapter()
    session.mount("https://", sentinel)
    assert session.get_adapter("https://idp.example/token") is sentinel
