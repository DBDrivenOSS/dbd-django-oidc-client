"""Verify the engine validates the ID token's claims, not just its signature.

A token whose signature is perfectly valid must still be rejected if its
audience or issuer is wrong, or if it has expired. Every token below is
correctly signed by the test key; only the claims differ.
"""

import time

import pytest
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, RSAKey

from dbd.oidc_client.client import OpenIDConfiguration, OpenIDConnectAuthorizationProvider

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
