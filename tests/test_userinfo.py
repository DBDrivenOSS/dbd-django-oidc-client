"""UserInfo: presenting an access token to the provider's userinfo endpoint.

Covers the client call without a live IdP by swapping the provider HTTP session
via ``OIDC_CLIENT["session"]``. That swap is also one of the assertions: userinfo
must run on the injected session rather than requests' defaults, so a custom
trust store or proxy governs it exactly as it governs discovery and JWKS.

The rejection test pins the contract resource servers depend on — a provider that
refuses the token surfaces as ``requests.HTTPError``, so "this credential is
invalid" is distinguishable from "the claims came back".
"""

import json

import pytest
import requests
from django.core.exceptions import ImproperlyConfigured

from dbd.oidc_client.client import OpenIDConfiguration, OpenIDConnectAuthorizationProvider

USERINFO = "https://idp.example/userinfo"
CLAIMS = {"sub": "user-123", "email": "person@example.com"}


def _provider(userinfo_endpoint=USERINFO):
    return OpenIDConnectAuthorizationProvider(
        redirect_uri="https://app.example/callback/",
        client_id="test-client",
        client_secret="secret",
        open_id_configuration=OpenIDConfiguration(
            authorization_endpoint="https://idp.example/authorize",
            token_endpoint="https://idp.example/token",
            userinfo_endpoint=userinfo_endpoint,
        ),
    )


def _response(status_code: int, payload: None | dict = None) -> requests.Response:
    """Build a real ``requests.Response`` so ``raise_for_status`` behaves for real."""
    response = requests.Response()
    response.status_code = status_code
    response.url = USERINFO
    response._content = json.dumps(payload if payload is not None else {}).encode()
    response.headers["Content-Type"] = "application/json"
    return response


class RecordingSession(requests.Session):
    """A session that answers every GET with one canned response, recording calls."""

    def __init__(self, response):
        super().__init__()
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


@pytest.fixture
def inject_session(settings):
    """Install a ``RecordingSession`` as ``OIDC_CLIENT["session"]`` and return it."""

    def _inject(response):
        session = RecordingSession(response)
        settings.OIDC_CLIENT = {**settings.OIDC_CLIENT, "session": session}
        return session

    return _inject


def test_userinfo_presents_bearer_token_and_returns_claims(inject_session):
    session = inject_session(_response(200, CLAIMS))

    claims = _provider().userinfo("an-access-token")

    assert claims == CLAIMS

    url, kwargs = session.calls[0]
    assert url == USERINFO
    assert kwargs["headers"]["Authorization"] == "Bearer an-access-token"


def test_userinfo_runs_on_the_injected_session(inject_session):
    # One injected session must govern every provider call, userinfo included.
    session = inject_session(_response(200, CLAIMS))

    _provider().userinfo("an-access-token")

    assert len(session.calls) == 1


def test_userinfo_without_endpoint_raises():
    # A provider whose discovery document advertises no userinfo endpoint is a
    # configuration problem, not a runtime one — fail before any network work.
    with pytest.raises(ImproperlyConfigured):
        _provider(userinfo_endpoint=None).userinfo("an-access-token")


def test_userinfo_raises_on_provider_rejection(inject_session):
    # The resource-server path: a 401 is the provider's verdict on the token.
    inject_session(_response(401, {"error": "invalid_token"}))

    with pytest.raises(requests.HTTPError):
        _provider().userinfo("a-revoked-token")


def test_userinfo_propagates_transport_failures(inject_session):
    session = inject_session(_response(200, CLAIMS))

    def boom(url, **kwargs):
        raise requests.ConnectionError("idp unreachable")

    session.get = boom

    with pytest.raises(requests.ConnectionError):
        _provider().userinfo("an-access-token")
