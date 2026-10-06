"""The ``next`` destination: followed after a sign in only when it is on this site.

The redirect view takes ``next`` from the query string, so anyone can write it,
and keeps it with the sign in attempt. The callback view sent the browser there
with no check of the host or the scheme. A link such as
``/auth/login/?next=https://attacker.example/`` ended a real sign in at the
provider with a redirect to another site, from the application's own address.

These tests cover that in five groups:

* store: what the redirect view keeps with the attempt;
* field: ``redirect_field_name`` names the query parameter the value comes in;
* follow: where the callback view sends the browser, for a value that came
  through the redirect view and for one an attempt already held;
* written: ``next`` is sent as it is written, and only ``success_url`` is read
  as a URL name;
* hosts: how a view allows a destination on another host on purpose.

No test reaches a network or a database. The provider is the real client with a
fixed nonce and a canned token exchange. The callback view's user lookup and
login are stubbed.
"""

import time
from types import SimpleNamespace

import pytest
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory

from dbd.oidc_client.client import (
    IDToken,
    OpenIDConfiguration,
    OpenIDConnectAuthorizationProvider,
)
from dbd.oidc_client.views import (
    PENDING_ATTEMPTS_SESSION_KEY,
    BaseOpenIDConnectCallbackView,
    BaseOpenIDConnectRedirectView,
)

ISSUER = "https://idp.example"
CLIENT_ID = "test-client"
NONCE = "n0nce"

# RequestFactory's host is "testserver". Each of these names another host, or
# is a shape a browser reads as one.
EXTERNAL_NEXT_VALUES = [
    "https://attacker.example/",
    "http://attacker.example/",
    "//attacker.example/",
    "///attacker.example/",
    "https:attacker.example",
    "/\\attacker.example/",
    "https://testserver.attacker.example/",
    "https://testserver@attacker.example/",
]

SAME_SITE_NEXT = "/reports/?year=2026&page=2"
PARTNER_NEXT = "https://partner.example/landing/"


class FakeSession(dict):
    """A dict that also tolerates ``session.modified = True``."""

    modified = False


class StubProvider(OpenIDConnectAuthorizationProvider):
    """The real client, with a fixed nonce and a token exchange that needs no network."""

    @staticmethod
    def generate_nonce() -> str:
        return NONCE

    def token(self, code, request=None, code_verifier=None):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "user-123",
            "email": "person@example.com",
            "iat": now,
            "exp": now + 3600,
            "nonce": NONCE,
        }
        return {"access_token": "an-access-token", "id_token": IDToken("raw.jwt", claims)}


class StubProviderMixin:
    """Give a view the stub provider in place of one built from discovery."""

    def get_oauth_client(self):
        return StubProvider(
            redirect_uri=self.get_redirect_uri(),
            client_id=CLIENT_ID,
            client_secret="secret",
            open_id_configuration=OpenIDConfiguration(
                authorization_endpoint=f"{ISSUER}/authorize",
                token_endpoint=f"{ISSUER}/token",
                issuer=ISSUER,
            ),
        )


class LoginView(StubProviderMixin, BaseOpenIDConnectRedirectView):
    """The library's redirect view, with the provider stubbed."""


class CallbackView(StubProviderMixin, BaseOpenIDConnectCallbackView):
    """The library's callback view, with the provider and the user store stubbed.

    ``get_success_url`` is the library's own.
    """

    success_url = "/home/"

    def get_or_create_user_from_claims(self, claims):
        return SimpleNamespace(email=claims.email)

    def login(self, user):
        self.request.signed_in = user


class ReturnToLoginView(LoginView):
    """A consumer whose login links carry the destination as ``return_to``."""

    redirect_field_name = "return_to"


class PartnerLoginView(LoginView):
    """A consumer that lets a sign in end on one other host."""

    success_url_allowed_hosts = {"partner.example"}


class PartnerCallbackView(CallbackView):
    """The callback half of the same consumer."""

    success_url_allowed_hosts = {"partner.example"}


def _request(path, session, secure=False, **params):
    request = RequestFactory().get(path, params, secure=secure)
    request.session = session
    return request


def _start(session, view_class=LoginView, secure=False, **params):
    """Run the redirect view, and return the state and the attempt it stored."""
    request = _request("/auth/login/", session, secure=secure, **params)

    response = view_class.as_view()(request)

    assert response.status_code == 302
    assert response.url.startswith(f"{ISSUER}/authorize?")

    ((state, attempt),) = session[PENDING_ATTEMPTS_SESSION_KEY].items()
    return state, attempt


def _finish(session, state, view_class=CallbackView, secure=False):
    """Run the callback view for ``state``, as the return from the provider does."""
    request = _request("/auth/callback/", session, secure=secure, state=state, code="a-code")

    response = view_class.as_view()(request)

    assert request.signed_in.email == "person@example.com"
    assert response.status_code == 302
    return response


def _sign_in(next_url, secure=False):
    """Run both views on one session, with ``next_url`` on the link that starts it."""
    session = FakeSession()
    state, _ = _start(session, secure=secure, next=next_url)

    return _finish(session, state, secure=secure)


def _holding(next_url):
    """Build a session whose pending attempt already holds ``next_url``.

    A session can hold a value that an earlier release stored with no check.
    """
    attempt = {"code_verifier": "verifier", "nonce": NONCE, "next": next_url}
    return FakeSession({PENDING_ATTEMPTS_SESSION_KEY: {"good-state": attempt}})


# --- store: what the redirect view keeps with the attempt -----------------


@pytest.mark.parametrize("external", EXTERNAL_NEXT_VALUES)
def test_external_next_is_not_stored(external):
    _, attempt = _start(FakeSession(), next=external)

    assert "next" not in attempt


def test_same_site_next_is_stored():
    _, attempt = _start(FakeSession(), next=SAME_SITE_NEXT)

    assert attempt["next"] == SAME_SITE_NEXT


def test_a_refused_next_still_starts_the_sign_in():
    # The value is dropped with no error, and the attempt is whole without it.
    _, attempt = _start(FakeSession(), next="https://attacker.example/")

    assert set(attempt) == {"code_verifier", "nonce"}


def test_a_secure_request_does_not_store_a_plain_http_next():
    # Over HTTPS, a plain HTTP address on this host is a step down.
    _, attempt = _start(FakeSession(), secure=True, next="http://testserver/reports/")

    assert "next" not in attempt


# --- field: redirect_field_name names the query parameter -----------------


def test_default_redirect_field_name_is_the_one_django_uses():
    assert BaseOpenIDConnectRedirectView.redirect_field_name == REDIRECT_FIELD_NAME == "next"


def test_redirect_field_name_names_the_query_parameter():
    session = FakeSession()
    state, attempt = _start(session, view_class=ReturnToLoginView, return_to=SAME_SITE_NEXT)

    # Kept as "next" whatever the parameter is called, so a callback view that
    # sets nothing finds it.
    assert attempt["next"] == SAME_SITE_NEXT

    response = _finish(session, state)

    assert response.url == SAME_SITE_NEXT


def test_a_view_with_another_field_name_does_not_read_next():
    _, attempt = _start(FakeSession(), view_class=ReturnToLoginView, next=SAME_SITE_NEXT)

    assert "next" not in attempt


@pytest.mark.parametrize("external", EXTERNAL_NEXT_VALUES)
def test_another_field_name_gets_the_same_check(external):
    _, attempt = _start(FakeSession(), view_class=ReturnToLoginView, return_to=external)

    assert "next" not in attempt


def test_a_redirect_field_name_of_none_carries_no_destination():
    class NoDestinationLoginView(LoginView):
        redirect_field_name = None

    _, attempt = _start(FakeSession(), view_class=NoDestinationLoginView, next=SAME_SITE_NEXT)

    assert "next" not in attempt


# --- follow: where the callback view sends the browser --------------------


@pytest.mark.parametrize("external", EXTERNAL_NEXT_VALUES)
def test_external_next_is_not_followed(external):
    # The whole trip: the link reaches a visitor, who then signs in for real.
    response = _sign_in(external)

    assert response.url == "/home/"


@pytest.mark.parametrize("external", EXTERNAL_NEXT_VALUES)
def test_external_next_already_held_with_an_attempt_is_not_followed(external):
    response = _finish(_holding(external), "good-state")

    assert response.url == "/home/"


def test_same_site_next_is_followed_end_to_end():
    response = _sign_in(SAME_SITE_NEXT)

    assert response.url == SAME_SITE_NEXT


def test_next_on_this_host_written_in_full_is_followed():
    response = _sign_in("http://testserver/reports/")

    assert response.url == "http://testserver/reports/"


def test_a_secure_request_follows_an_https_next_on_this_host():
    response = _sign_in("https://testserver/reports/", secure=True)

    assert response.url == "https://testserver/reports/"


def test_a_secure_request_does_not_follow_a_plain_http_next_it_holds():
    response = _finish(_holding("http://testserver/reports/"), "good-state", secure=True)

    assert response.url == "/home/"


def test_a_sign_in_with_no_next_goes_to_success_url():
    session = FakeSession()
    state, _ = _start(session)

    response = _finish(session, state)

    assert response.url == "/home/"


def test_a_held_value_that_is_not_text_is_not_followed():
    # The session is the application's to write, so the type is not a given.
    response = _finish(_holding(["https://attacker.example/"]), "good-state")

    assert response.url == "/home/"


def test_a_refused_next_with_no_success_url_is_a_configuration_error():
    # Nothing else to fall back on is no reason to follow the value.
    class NoSuccessUrlCallbackView(CallbackView):
        success_url = None

    request = _request(
        "/auth/callback/", _holding("https://attacker.example/"), state="good-state", code="a-code"
    )

    with pytest.raises(ImproperlyConfigured):
        NoSuccessUrlCallbackView.as_view()(request)


# --- written: next is sent as it is, success_url is read as a URL name ----


def test_next_that_is_not_a_url_name_does_not_raise():
    # resolve_url() reads a bare word as a URL name, and raises when there is none.
    response = _sign_in("no-such-url-name")

    assert response.url == "no-such-url-name"


def test_next_that_is_a_url_name_is_not_reversed():
    # Reversed, this one signed the visitor out again right after the sign in.
    response = _sign_in("oidc_client:logout")

    assert response.url == "oidc_client:logout"


def test_success_url_is_still_read_as_a_url_name():
    class NamedCallbackView(CallbackView):
        success_url = "oidc_client:login"

    session = FakeSession()
    state, _ = _start(session)

    response = _finish(session, state, view_class=NamedCallbackView)

    assert response.url == "/auth/login/"


# --- hosts: how a view allows a destination on another host ---------------


def test_default_allowed_host_is_the_host_of_the_request():
    view = CallbackView()
    view.request = _request("/auth/callback/", FakeSession())

    assert view.get_success_url_allowed_hosts() == {"testserver"}


def test_a_host_both_views_allow_is_stored_and_followed():
    session = FakeSession()
    state, attempt = _start(session, view_class=PartnerLoginView, next=PARTNER_NEXT)
    assert attempt["next"] == PARTNER_NEXT

    response = _finish(session, state, view_class=PartnerCallbackView)

    assert response.url == PARTNER_NEXT


def test_allowing_one_host_does_not_allow_another():
    _, attempt = _start(
        FakeSession(), view_class=PartnerLoginView, next="https://attacker.example/"
    )
    assert "next" not in attempt

    response = _finish(
        _holding("https://attacker.example/"), "good-state", view_class=PartnerCallbackView
    )

    assert response.url == "/home/"


def test_the_callback_view_does_not_trust_what_the_redirect_view_allowed():
    # Only the redirect view allows the host, so the callback view refuses it.
    session = FakeSession()
    state, attempt = _start(session, view_class=PartnerLoginView, next=PARTNER_NEXT)
    assert attempt["next"] == PARTNER_NEXT

    response = _finish(session, state)

    assert response.url == "/home/"


def test_get_success_url_allowed_hosts_can_be_overridden():
    class TenantCallbackView(CallbackView):
        def get_success_url_allowed_hosts(self):
            return {*super().get_success_url_allowed_hosts(), "partner.example"}

    response = _finish(_holding(PARTNER_NEXT), "good-state", view_class=TenantCallbackView)

    assert response.url == PARTNER_NEXT
