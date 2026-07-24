"""RP-initiated logout: the client end-session redirect and the logout view.

Logout has two layers, tested here without a live IdP:

* client — ``end_session_redirect`` builds the provider's end-session URL from the
  discovery ``end_session_endpoint``, carrying ``client_id``, an absolutized
  ``post_logout_redirect_uri``, and the ``id_token_hint``; it refuses when the
  provider advertises no endpoint.
* view — ``BaseOpenIDConnectLogoutView`` always clears the local session, then
  bounces through the provider only when RP-initiated logout is enabled and a
  stored ``id_token_hint`` is present, falling back to a local redirect otherwise.

The view tests drive the class directly with a fake request and override
``get_oauth_client`` so no network or discovery fetch happens.
"""

from types import SimpleNamespace
from urllib.parse import parse_qs, urljoin, urlparse

import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured

from dbd.oidc_client.client import OpenIDConfiguration, OpenIDConnectAuthorizationProvider
from dbd.oidc_client.views import ID_TOKEN_HINT_SESSION_KEY, BaseOpenIDConnectLogoutView

END_SESSION = "https://idp.example/logout"


def _provider(end_session_endpoint=END_SESSION):
    return OpenIDConnectAuthorizationProvider(
        redirect_uri="https://app.example/callback/",
        client_id="test-client",
        client_secret="secret",
        open_id_configuration=OpenIDConfiguration(
            authorization_endpoint="https://idp.example/authorize",
            token_endpoint="https://idp.example/token",
            end_session_endpoint=end_session_endpoint,
        ),
    )


def _query(response) -> dict:
    """Parse a redirect response's query string into a ``{key: [values]}`` dict."""
    return parse_qs(urlparse(response.url).query)


# --- client: end_session_redirect ---------------------------------------


def test_end_session_redirect_carries_hint_and_absolute_post_logout_uri():
    response = _provider().end_session_redirect(
        post_logout_redirect_uri="https://app.example/bye/",
        id_token_hint="raw.jwt.hint",
    )

    assert response.status_code == 302
    assert urlparse(response.url)._replace(query="").geturl() == END_SESSION

    query = _query(response)
    assert query["client_id"] == ["test-client"]
    assert query["post_logout_redirect_uri"] == ["https://app.example/bye/"]
    assert query["id_token_hint"] == ["raw.jwt.hint"]


def test_end_session_redirect_omits_absent_optional_params():
    # With neither a post-logout URI nor a hint, only client_id rides along.
    response = _provider().end_session_redirect()

    query = _query(response)
    assert query == {"client_id": ["test-client"]}


def test_end_session_redirect_absolutizes_a_relative_post_logout_uri():
    request = SimpleNamespace(build_absolute_uri=lambda path: urljoin("https://app.example/", path))

    response = _provider().end_session_redirect(
        post_logout_redirect_uri="/bye/",
        request=request,
    )

    assert _query(response)["post_logout_redirect_uri"] == ["https://app.example/bye/"]


def test_end_session_redirect_without_endpoint_raises():
    provider = _provider(end_session_endpoint=None)

    with pytest.raises(ImproperlyConfigured):
        provider.end_session_redirect(id_token_hint="raw.jwt.hint")


# --- view: BaseOpenIDConnectLogoutView -----------------------------------


class FakeSession(dict):
    """A dict that also honors ``flush()`` and ``session.modified = True``."""

    modified = False
    flushed = False

    def flush(self):
        self.flushed = True
        self.clear()


def _forbid_client():
    raise AssertionError("get_oauth_client() must not be called on a local-only logout.")


def _logout_view(session=None, oauth_client=_forbid_client, **attrs):
    """Build a logout view wired to a fake request, stubbing the OAuth client.

    By default ``get_oauth_client`` raises, asserting the local-only paths never
    reach for the provider (and so never hit discovery). Pass ``oauth_client`` a
    zero-arg callable returning a provider for the RP-initiated paths.
    """
    view = BaseOpenIDConnectLogoutView()
    for name, value in attrs.items():
        setattr(view, name, value)

    view.request = SimpleNamespace(
        session=session if session is not None else FakeSession(),
        user=AnonymousUser(),
        GET={},
        build_absolute_uri=lambda path: urljoin("https://app.example/", path),
    )
    view.get_oauth_client = oauth_client
    return view


def test_local_only_logout_when_no_id_token_hint():
    # No stored hint: the session is cleared and we redirect locally, never
    # touching the provider (get_oauth_client would raise if it were called).
    view = _logout_view(session=FakeSession(other="keep-until-flush"))

    response = view.get(view.request)

    assert view.request.session.flushed is True
    assert response.status_code == 302
    assert response.url == "https://app.example/"


def test_rp_initiated_logout_redirects_through_the_provider():
    session = FakeSession({ID_TOKEN_HINT_SESSION_KEY: "raw.jwt.hint"})
    view = _logout_view(session=session, oauth_client=_provider)

    response = view.get(view.request)

    assert session.flushed is True
    assert urlparse(response.url)._replace(query="").geturl() == END_SESSION
    query = _query(response)
    assert query["id_token_hint"] == ["raw.jwt.hint"]
    assert query["post_logout_redirect_uri"] == ["https://app.example/"]


def test_rp_initiated_falls_back_to_local_when_provider_has_no_end_session():
    # Provider advertises no end-session endpoint: end_session_redirect raises
    # ImproperlyConfigured, and the view degrades to a local redirect.
    session = FakeSession({ID_TOKEN_HINT_SESSION_KEY: "raw.jwt.hint"})
    view = _logout_view(session=session, oauth_client=lambda: _provider(end_session_endpoint=None))

    response = view.get(view.request)

    assert response.status_code == 302
    assert response.url == "https://app.example/"


def test_rp_initiated_disabled_stays_local_even_with_a_hint():
    # rp_initiated off: the hint is still cleared from the session, but the
    # provider is never consulted.
    session = FakeSession({ID_TOKEN_HINT_SESSION_KEY: "raw.jwt.hint"})
    view = _logout_view(session=session, rp_initiated=False)

    response = view.get(view.request)

    assert response.url == "https://app.example/"
    assert ID_TOKEN_HINT_SESSION_KEY not in session


def test_custom_post_logout_redirect_uri_is_honored():
    view = _logout_view(post_logout_redirect_uri="/goodbye/")

    response = view.get(view.request)

    assert response.url == "https://app.example/goodbye/"
