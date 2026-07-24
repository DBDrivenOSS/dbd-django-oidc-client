"""Verify the engine validates the ID token's claims, not just its signature.

A token whose signature is perfectly valid must still be rejected if its
audience or issuer is wrong, or if it has expired. Every token below is
correctly signed by the test key; only the claims differ.
"""

import json
import time

import pytest
from authlib.integrations.requests_client import OAuth2Session
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, RSAKey

from dbd.oidc_client.client import (
    IDToken,
    OpenIDConfiguration,
    OpenIDConnectAuthorizationProvider,
)

ISSUER = "https://idp.example"
CLIENT_ID = "test-client"


@pytest.fixture
def signing_key():
    return RSAKey.generate_key(2048, auto_kid=True)


@pytest.fixture
def provider(signing_key, monkeypatch):
    config = OpenIDConfiguration(
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        issuer=ISSUER,
        jwks_uri=f"{ISSUER}/jwks",
    )

    # Mirror production: import the provider's *public* JWKS into a key set.
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


def test_valid_id_token_passes(provider, signing_key):
    claims = provider.validate_id_token(_sign(signing_key))
    assert claims["sub"] == "user-123"
    assert claims["email"] == "person@example.com"


def test_wrong_audience_is_rejected(provider, signing_key):
    # Correctly signed, but issued for a different client — must fail.
    with pytest.raises(JoseError):
        provider.validate_id_token(_sign(signing_key, aud="some-other-client"))


def test_wrong_issuer_is_rejected(provider, signing_key):
    with pytest.raises(JoseError):
        provider.validate_id_token(_sign(signing_key, iss="https://evil.example"))


def test_expired_token_is_rejected(provider, signing_key):
    past = int(time.time()) - 3600
    with pytest.raises(JoseError):
        provider.validate_id_token(_sign(signing_key, iat=past, exp=past + 60))


# --- refresh grant -------------------------------------------------------


def _stub_refresh(monkeypatch, response: dict):
    """Make ``OAuth2Session.refresh_token`` return ``response`` without a network call."""
    monkeypatch.setattr(
        OAuth2Session,
        "refresh_token",
        lambda self, url, refresh_token=None, **kwargs: dict(response),
    )


def test_refresh_validates_and_wraps_returned_id_token(provider, signing_key, monkeypatch):
    # A provider that returns an id_token on refresh — it must be validated and
    # wrapped just like the code exchange does.
    _stub_refresh(
        monkeypatch,
        {
            "access_token": "fresh-access",
            "refresh_token": "rotated-refresh",
            "id_token": _sign(signing_key),
            "expires_in": 3600,
        },
    )

    result = provider.refresh("old-refresh")

    assert result["access_token"] == "fresh-access"
    assert isinstance(result["id_token"], IDToken)
    assert json.loads(result["id_token"].claims)["sub"] == "user-123"


def test_refresh_without_id_token_passes_through(provider, monkeypatch):
    # django-oauth-toolkit and others omit the id_token on refresh; the response
    # must come back intact with no id_token key (and nothing to validate).
    _stub_refresh(
        monkeypatch,
        {
            "access_token": "fresh-access",
            "refresh_token": "rotated-refresh",
            "expires_in": 3600,
        },
    )

    result = provider.refresh("old-refresh")

    assert result["access_token"] == "fresh-access"
    assert "id_token" not in result


def test_refresh_rejects_an_invalid_returned_id_token(provider, signing_key, monkeypatch):
    # A bad id_token on refresh is still a bad id_token — validation must fire.
    _stub_refresh(
        monkeypatch,
        {"access_token": "fresh-access", "id_token": _sign(signing_key, aud="someone-else")},
    )

    with pytest.raises(JoseError):
        provider.refresh("old-refresh")


def test_refresh_propagates_token_endpoint_errors(provider, monkeypatch):
    def boom(self, url, refresh_token=None, **kwargs):
        raise RuntimeError("invalid_grant")

    monkeypatch.setattr(OAuth2Session, "refresh_token", boom)

    with pytest.raises(RuntimeError):
        provider.refresh("expired-refresh")
