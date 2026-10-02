"""Error handling: every way a sign in can stop short of a session.

On 2026-10-02 a provider sent a person back to the callback with
``error=access_denied`` in place of a code. The callback ignored ``error``,
tried to exchange a code it never got, and the person saw a 500. These tests
cover that return and the other failures, in four groups:

* hierarchy: every error is an ``OIDCError``, and each one is still an instance
  of the type that leaked from the same place before, so an earlier ``except``
  clause keeps working;
* callback: what ``oidc_callback`` raises before it calls the provider;
* engine: how Authlib, joserfc, and requests failures are reported;
* hooks: ``handle_callback_error`` and ``handle_redirect_error``, and what
  Django answers when nothing overrides them.

No test reaches a network. The provider is a stub client, a stubbed
``OAuth2Session.fetch_token``, or a session swapped in through
``OIDC_CLIENT["session"]``.
"""

import json
import time
from types import SimpleNamespace

import pytest
import requests
from authlib.integrations.base_client import OAuthError
from authlib.integrations.requests_client import OAuth2Session
from django.core.cache import cache
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse
from django.test import RequestFactory
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from dbd.oidc_client.client import (
    IDToken,
    OpenIDConfiguration,
    OpenIDConnectAuthorizationProvider,
)
from dbd.oidc_client.exceptions import (
    AuthorizationErrorResponse,
    IDTokenValidationError,
    MissingAuthorizationCode,
    NonceMismatch,
    OIDCError,
    ProviderHTTPError,
    ProviderUnreachable,
    StateMismatch,
    TokenExchangeError,
)
from dbd.oidc_client.views import (
    PENDING_ATTEMPTS_SESSION_KEY,
    BaseOpenIDConnectCallbackView,
    BaseOpenIDConnectRedirectView,
)

ISSUER = "https://idp.example"
CLIENT_ID = "test-client"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks"
DISCOVERY_DOCUMENT = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": JWKS_URL,
}

# What a provider sends when the account is not assigned to the application.
NOT_ASSIGNED = {
    "error": "access_denied",
    "error_description": "marker-9f3 <b>User is not assigned</b>",
    "error_uri": "https://idp.example/errors/marker-9f3",
}


@pytest.fixture(autouse=True)
def _empty_cache():
    """Discovery, JWKS, and the test sessions all live in the cache."""
    cache.clear()
    yield
    cache.clear()


def _pending(nonce="n0nce"):
    return {"good-state": {"code_verifier": "verifier", "nonce": nonce, "next": "/a/"}}


class FakeSession(dict):
    """A dict that also tolerates ``session.modified = True``."""

    modified = False


def _forbid_client():
    raise AssertionError("The provider must not be called for this callback.")


class StubClient:
    """A provider client whose token exchange succeeds with one canned nonce."""

    def __init__(self, nonce):
        self.nonce = nonce
        self.calls = []

    def token(self, code, request=None, code_verifier=None):
        self.calls.append({"code": code, "code_verifier": code_verifier})
        return {"access_token": "an-access-token", "id_token": IDToken("raw.jwt", self._claims())}

    def _claims(self):
        now = int(time.time())
        return {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-123",
            "email": "person@example.com",
            "iat": now,
            "exp": now + 3600,
            "nonce": self.nonce,
        }


def _callback_view(pending=None, oauth_client=_forbid_client, **get_params):
    """Build a callback view on a fake request, with the provider stubbed."""
    session = FakeSession()
    if pending is not None:
        session[PENDING_ATTEMPTS_SESSION_KEY] = pending

    view = BaseOpenIDConnectCallbackView()
    view.request = SimpleNamespace(session=session, GET=dict(get_params))
    view.get_oauth_client = oauth_client
    return view


# --- hierarchy: one root, and the types earlier releases leaked -----------


@pytest.mark.parametrize(
    "error_class",
    [
        StateMismatch,
        AuthorizationErrorResponse,
        MissingAuthorizationCode,
        ProviderUnreachable,
        ProviderHTTPError,
        TokenExchangeError,
        IDTokenValidationError,
        NonceMismatch,
    ],
)
def test_every_error_is_an_oidc_error(error_class):
    assert issubclass(error_class, OIDCError)


@pytest.mark.parametrize(
    "error_class",
    [StateMismatch, AuthorizationErrorResponse, MissingAuthorizationCode, NonceMismatch],
)
def test_callback_rejections_are_still_suspicious_operations(error_class):
    # Django answers a SuspiciousOperation with a 400, and consumers catch it.
    assert issubclass(error_class, SuspiciousOperation)


def test_provider_unreachable_is_still_a_requests_exception():
    exc = ProviderUnreachable("discovery")

    assert isinstance(exc, requests.RequestException)
    assert not isinstance(exc, requests.HTTPError)
    assert exc.stage == "discovery"
    assert "discovery" in str(exc)


def test_provider_http_error_is_still_a_requests_http_error():
    exc = ProviderHTTPError("token")

    assert isinstance(exc, ProviderUnreachable)
    assert isinstance(exc, requests.HTTPError)
    assert exc.stage == "token"


def test_authorization_error_text_stays_out_of_str_and_repr():
    # The query string is the visitor's to write, so the message never repeats it.
    exc = AuthorizationErrorResponse(
        "marker-error", description="marker-description", uri="https://evil.example/marker-uri"
    )

    assert "marker" not in str(exc)
    assert "marker" not in repr(exc)
    assert exc.error == "marker-error"
    assert exc.description == "marker-description"
    assert exc.uri == "https://evil.example/marker-uri"


# --- callback: what oidc_callback raises before it calls the provider -----


def test_error_response_is_raised_before_any_token_exchange():
    # _forbid_client fails the test if the view reaches for the provider.
    view = _callback_view(pending=_pending(), state="good-state", **NOT_ASSIGNED)

    with pytest.raises(AuthorizationErrorResponse) as raised:
        view.oidc_callback()

    assert raised.value.error == "access_denied"
    assert raised.value.description == NOT_ASSIGNED["error_description"]
    assert raised.value.uri == NOT_ASSIGNED["error_uri"]


def test_error_response_without_optional_parameters():
    view = _callback_view(pending=_pending(), state="good-state", error="server_error")

    with pytest.raises(AuthorizationErrorResponse) as raised:
        view.oidc_callback()

    assert raised.value.error == "server_error"
    assert raised.value.description is None
    assert raised.value.uri is None


def test_error_response_consumes_the_matched_attempt():
    view = _callback_view(pending=_pending(), state="good-state", **NOT_ASSIGNED)

    with pytest.raises(AuthorizationErrorResponse):
        view.oidc_callback()

    assert view.request.session[PENDING_ATTEMPTS_SESSION_KEY] == {}

    # The same callback a second time has no attempt left to match.
    with pytest.raises(StateMismatch):
        view.oidc_callback()


def test_error_response_with_an_unknown_state_is_a_state_mismatch():
    # Nothing ties this error to a sign in this session started.
    view = _callback_view(pending=_pending(), state="never-issued", **NOT_ASSIGNED)

    with pytest.raises(StateMismatch):
        view.oidc_callback()

    # The attempt the session does hold is left alone.
    assert "good-state" in view.request.session[PENDING_ATTEMPTS_SESSION_KEY]


def test_error_response_without_a_state_is_a_state_mismatch():
    view = _callback_view(pending=_pending(), **NOT_ASSIGNED)

    with pytest.raises(StateMismatch):
        view.oidc_callback()


def test_unknown_state_is_a_state_mismatch():
    view = _callback_view(state="never-issued", code="a-code")

    with pytest.raises(StateMismatch, match="does not match any pending login"):
        view.oidc_callback()


def test_callback_without_code_or_error_is_refused_before_any_token_exchange():
    view = _callback_view(pending=_pending(), state="good-state")

    with pytest.raises(MissingAuthorizationCode):
        view.oidc_callback()

    assert view.request.session[PENDING_ATTEMPTS_SESSION_KEY] == {}


def test_nonce_mismatch_is_raised_after_the_exchange():
    client = StubClient(nonce="some-other-nonce")
    view = _callback_view(
        pending=_pending(), oauth_client=lambda: client, state="good-state", code="a-code"
    )

    with pytest.raises(NonceMismatch, match="nonce does not match"):
        view.oidc_callback()

    assert client.calls == [{"code": "a-code", "code_verifier": "verifier"}]


def test_a_good_callback_still_returns_the_token_response():
    client = StubClient(nonce="n0nce")
    view = _callback_view(
        pending=_pending(), oauth_client=lambda: client, state="good-state", code="a-code"
    )

    token_response = view.oidc_callback()

    assert token_response["access_token"] == "an-access-token"
    assert view.attempt_extra == {"next": "/a/"}
    assert view.request.session[PENDING_ATTEMPTS_SESSION_KEY] == {}


# --- engine: how the provider's failures are reported ---------------------


@pytest.fixture
def signing_key():
    return RSAKey.generate_key(2048, auto_kid=True)


@pytest.fixture
def provider(signing_key, monkeypatch):
    config = OpenIDConfiguration(
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        issuer=ISSUER,
        jwks_uri=JWKS_URL,
    )

    public_jwks = {"keys": [signing_key.as_dict(private=False)]}
    key_set = KeySet.import_key_set(public_jwks)
    monkeypatch.setattr(config, "load_jwks", lambda: key_set)

    return OpenIDConnectAuthorizationProvider(
        redirect_uri="https://app.example/callback/",
        client_id=CLIENT_ID,
        client_secret="secret",
        open_id_configuration=config,
    )


def _sign(signing_key, **overrides) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "email": "person@example.com",
        "iat": now,
        "exp": now + 3600,
        "nonce": "n0nce",
    }
    payload.update(overrides)

    header = {"alg": "RS256", "kid": signing_key.kid}
    return jwt.encode(header, payload, signing_key)


def _stub_fetch_token(monkeypatch, outcome):
    """Make ``OAuth2Session.fetch_token`` return, or raise, ``outcome``."""

    def fetch_token(self, url=None, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome

        return dict(outcome)

    monkeypatch.setattr(OAuth2Session, "fetch_token", fetch_token)


def _response(status_code: int, payload: None | dict = None, url=DISCOVERY_URL):
    """Build a real ``requests.Response`` so ``raise_for_status`` behaves for real."""
    response = requests.Response()
    response.status_code = status_code
    response.url = url
    response._content = json.dumps(payload if payload is not None else {}).encode()
    response.headers["Content-Type"] = "application/json"
    return response


class StubSession(requests.Session):
    """A session whose every GET returns, or raises, one canned outcome."""

    def __init__(self, outcome):
        super().__init__()
        self.outcome = outcome
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        if isinstance(self.outcome, Exception):
            raise self.outcome

        return self.outcome


@pytest.fixture
def inject_session(settings):
    """Install a ``StubSession`` as ``OIDC_CLIENT["session"]`` and return it."""

    def _inject(outcome):
        session = StubSession(outcome)
        settings.OIDC_CLIENT = {**settings.OIDC_CLIENT, "session": session}
        return session

    return _inject


def test_token_endpoint_refusal_is_a_token_exchange_error(provider, monkeypatch):
    refusal = OAuthError(error="invalid_grant", description="The code has expired.")
    _stub_fetch_token(monkeypatch, refusal)

    with pytest.raises(TokenExchangeError) as raised:
        provider.token(code="an-expired-code")

    assert raised.value.error == "invalid_grant"
    assert raised.value.description == "The code has expired."
    assert raised.value.__cause__ is refusal
    assert "invalid_grant" in str(raised.value)
    assert "The code has expired." not in str(raised.value)


def test_token_endpoint_transport_failure_is_provider_unreachable(provider, monkeypatch):
    failure = requests.ConnectionError("idp unreachable")
    _stub_fetch_token(monkeypatch, failure)

    with pytest.raises(ProviderUnreachable) as raised:
        provider.token(code="a-code")

    assert raised.value.stage == "token"
    assert raised.value.__cause__ is failure
    assert isinstance(raised.value, requests.RequestException)
    assert not isinstance(raised.value, requests.HTTPError)


def test_token_endpoint_server_error_is_still_a_requests_http_error(provider, monkeypatch):
    # Authlib raises requests.HTTPError for a 5xx answer, and a consumer that
    # catches HTTPError around oidc_callback() must still catch it.
    answer = _response(503, url=f"{ISSUER}/token")
    _stub_fetch_token(monkeypatch, requests.HTTPError("503 Server Error", response=answer))

    with pytest.raises(requests.HTTPError) as raised:
        provider.token(code="a-code")

    assert isinstance(raised.value, ProviderHTTPError)
    assert raised.value.stage == "token"
    assert raised.value.response is answer


def test_unrelated_token_exchange_failures_are_not_disguised(provider, monkeypatch):
    _stub_fetch_token(monkeypatch, RuntimeError("a bug, not a provider answer"))

    with pytest.raises(RuntimeError):
        provider.token(code="a-code")


def test_invalid_id_token_is_an_id_token_validation_error(provider, signing_key, monkeypatch):
    # Correctly signed, but issued for a different client.
    _stub_fetch_token(
        monkeypatch,
        {"access_token": "an-access-token", "id_token": _sign(signing_key, aud="someone-else")},
    )

    with pytest.raises(IDTokenValidationError) as raised:
        provider.token(code="a-code")

    assert raised.value.__cause__ is not None


def test_token_response_without_an_id_token_is_an_id_token_validation_error(provider, monkeypatch):
    _stub_fetch_token(monkeypatch, {"access_token": "an-access-token"})

    with pytest.raises(IDTokenValidationError):
        provider.token(code="a-code")


def test_a_valid_exchange_still_returns_a_validated_id_token(provider, signing_key, monkeypatch):
    _stub_fetch_token(
        monkeypatch, {"access_token": "an-access-token", "id_token": _sign(signing_key)}
    )

    token_response = provider.token(code="a-code")

    assert isinstance(token_response["id_token"], IDToken)
    assert json.loads(token_response["id_token"].claims)["sub"] == "user-123"


def test_jwks_failure_during_the_exchange_is_provider_unreachable(
    signing_key, monkeypatch, inject_session
):
    # The token endpoint answered. The signing keys cannot be fetched, which is
    # the provider's fault and not the token's.
    inject_session(requests.ConnectionError("jwks unreachable"))
    _stub_fetch_token(
        monkeypatch, {"access_token": "an-access-token", "id_token": _sign(signing_key)}
    )
    provider = OpenIDConnectAuthorizationProvider(
        redirect_uri="https://app.example/callback/",
        client_id=CLIENT_ID,
        client_secret="secret",
        open_id_configuration=OpenIDConfiguration(
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            issuer=ISSUER,
            jwks_uri=JWKS_URL,
        ),
    )

    with pytest.raises(ProviderUnreachable) as raised:
        provider.token(code="a-code")

    assert raised.value.stage == "jwks"


def test_discovery_transport_failure_is_provider_unreachable(inject_session):
    failure = requests.ConnectionError("idp unreachable")
    inject_session(failure)

    with pytest.raises(ProviderUnreachable) as raised:
        OpenIDConfiguration.from_config_url(DISCOVERY_URL)

    assert raised.value.stage == "discovery"
    assert raised.value.__cause__ is failure


def test_discovery_error_status_is_provider_unreachable(inject_session):
    # A 503 with a JSON body used to be parsed as the discovery document.
    inject_session(_response(503, {"error": "temporarily_unavailable"}))

    with pytest.raises(ProviderHTTPError) as raised:
        OpenIDConfiguration.from_config_url(DISCOVERY_URL)

    assert raised.value.stage == "discovery"
    assert raised.value.response.status_code == 503


def test_discovery_failure_is_not_cached(inject_session):
    inject_session(requests.ConnectionError("idp unreachable"))

    with pytest.raises(ProviderUnreachable):
        OpenIDConfiguration.from_config_url(DISCOVERY_URL)

    # The provider comes back, and the next attempt reads the real document.
    inject_session(_response(200, DISCOVERY_DOCUMENT))

    config = OpenIDConfiguration.from_config_url(DISCOVERY_URL)

    assert config.token_endpoint == f"{ISSUER}/token"


def test_jwks_transport_failure_is_provider_unreachable(inject_session):
    inject_session(requests.Timeout("jwks timed out"))
    config = OpenIDConfiguration(
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=JWKS_URL,
    )

    with pytest.raises(ProviderUnreachable) as raised:
        config.load_jwks()

    assert raised.value.stage == "jwks"


# --- hooks: handle_callback_error and handle_redirect_error ----------------


def _request(path, session=None, **params):
    request = RequestFactory().get(path, params)
    request.session = session if session is not None else FakeSession()
    return request


def _callback_request(**params):
    session = FakeSession({PENDING_ATTEMPTS_SESSION_KEY: _pending()})
    return _request("/auth/callback/", session=session, **params)


class AnsweringCallbackView(BaseOpenIDConnectCallbackView):
    """A consumer that answers every failed sign in with a page of its own."""

    success_url = "/home/"

    def handle_callback_error(self, exc):
        self.request.handled = exc
        return HttpResponse("The sign in did not finish.", status=403)


class AccountRefused(OIDCError):
    """An application's own refusal, raised from its user lookup."""


class RefusingCallbackView(AnsweringCallbackView):
    """A consumer whose user lookup refuses the account the provider vouched for."""

    def oidc_callback(self):
        return StubClient(nonce="n0nce").token(code="a-code")

    def get_or_create_user_from_claims(self, claims):
        raise AccountRefused("This account is deactivated.")


class BrokenCallbackView(AnsweringCallbackView):
    """A consumer whose callback fails with something that is not an ``OIDCError``."""

    def oidc_callback(self):
        raise RuntimeError("a bug, not a failed sign in")


class AnsweringRedirectView(BaseOpenIDConnectRedirectView):
    """A consumer that answers a sign in that could not start."""

    def handle_redirect_error(self, exc):
        self.request.handled = exc
        return HttpResponse("The provider did not answer.", status=502)


def test_callback_hook_default_raises_the_error_again():
    request = _callback_request(state="good-state", **NOT_ASSIGNED)

    with pytest.raises(AuthorizationErrorResponse):
        BaseOpenIDConnectCallbackView.as_view()(request)


def test_callback_hook_can_answer_with_its_own_response():
    request = _callback_request(state="good-state", **NOT_ASSIGNED)

    response = AnsweringCallbackView.as_view()(request)

    assert response.status_code == 403
    assert isinstance(request.handled, AuthorizationErrorResponse)
    assert request.handled.error == "access_denied"


def test_callback_hook_receives_a_stale_state():
    request = _callback_request(state="never-issued", code="a-code")

    response = AnsweringCallbackView.as_view()(request)

    assert response.status_code == 403
    assert isinstance(request.handled, StateMismatch)


def test_callback_hook_receives_the_applications_own_oidc_errors():
    request = _callback_request(state="good-state", code="a-code")

    response = RefusingCallbackView.as_view()(request)

    assert response.status_code == 403
    assert isinstance(request.handled, AccountRefused)


def test_callback_hook_is_not_given_other_exceptions():
    request = _callback_request(state="good-state", code="a-code")

    with pytest.raises(RuntimeError):
        BrokenCallbackView.as_view()(request)

    assert not hasattr(request, "handled")


def test_redirect_hook_default_raises_the_error_again(inject_session):
    # Runs the real client builder: the discovery fetch is what fails.
    inject_session(requests.ConnectionError("idp unreachable"))
    request = _request("/auth/login/")

    with pytest.raises(ProviderUnreachable) as raised:
        BaseOpenIDConnectRedirectView.as_view()(request)

    assert raised.value.stage == "discovery"
    assert isinstance(raised.value, requests.RequestException)


def test_redirect_hook_can_answer_with_its_own_response(inject_session):
    inject_session(requests.ConnectionError("idp unreachable"))
    request = _request("/auth/login/")

    response = AnsweringRedirectView.as_view()(request)

    assert response.status_code == 502
    assert isinstance(request.handled, ProviderUnreachable)
    assert request.session.get(PENDING_ATTEMPTS_SESSION_KEY) is None


def test_redirect_still_starts_the_flow_when_the_provider_answers(inject_session):
    inject_session(_response(200, DISCOVERY_DOCUMENT))
    request = _request("/auth/login/", next="/a/")

    response = AnsweringRedirectView.as_view()(request)

    assert response.status_code == 302
    assert response.url.startswith(f"{ISSUER}/authorize?")
    assert not hasattr(request, "handled")

    (attempt,) = request.session[PENDING_ATTEMPTS_SESSION_KEY].values()
    assert attempt["next"] == "/a/"


# --- what Django answers when no hook is overridden ------------------------


@pytest.fixture
def browser(settings, client):
    """A test client with a real session, kept in the cache (no database)."""
    settings.MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]
    settings.SESSION_ENGINE = "django.contrib.sessions.backends.cache"
    return client


def _start_attempt(browser):
    session = browser.session
    session[PENDING_ATTEMPTS_SESSION_KEY] = _pending()
    session.save()


def test_default_answer_to_a_stale_state_is_still_a_400(browser):
    response = browser.get("/auth/callback/", {"state": "never-issued", "code": "a-code"})

    assert response.status_code == 400


def test_default_answer_to_an_error_response_is_a_400_that_repeats_nothing(browser):
    _start_attempt(browser)

    response = browser.get("/auth/callback/", {"state": "good-state", **NOT_ASSIGNED})

    assert response.status_code == 400
    assert "marker-9f3" not in response.content.decode()
    assert browser.session[PENDING_ATTEMPTS_SESSION_KEY] == {}
