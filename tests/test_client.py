"""Crypto and claims unit tests that need no live IdP."""

import json

from dbd.oidc_client.claims import OpenIDClaims
from dbd.oidc_client.client import OpenIDConnectAuthorizationProvider


class FakeToken:
    """Stand-in for a validated jwcrypto JWT — exposes ``.claims`` as JSON text."""

    def __init__(self, claims: dict):
        self.claims = json.dumps(claims)


def test_code_challenge_matches_rfc7636_vector():
    # The canonical example from RFC 7636 Appendix B.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = OpenIDConnectAuthorizationProvider.generate_code_challenge(verifier)
    assert challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_code_verifier_is_unreserved_and_correct_length():
    verifier = OpenIDConnectAuthorizationProvider.generate_code_verifier()
    assert 43 <= len(verifier) <= 128
    assert all(c.isalnum() or c in "-._~" for c in verifier)


def test_code_verifiers_are_unique():
    verifiers = {OpenIDConnectAuthorizationProvider.generate_code_verifier() for _ in range(100)}
    assert len(verifiers) == 100


def test_is_absolute_uri():
    assert OpenIDConnectAuthorizationProvider.is_absolute_uri("https://idp.example/auth")
    assert not OpenIDConnectAuthorizationProvider.is_absolute_uri("/callback/")


def test_openid_claims_from_jwt():
    token = FakeToken(
        {
            "aud": "client",
            "exp": 1700000000,
            "iss": "https://idp.example",
            "iat": 1699999000,
            "sub": "subject-123",
            "email": "Person@Example.com",
            "nonce": "abc",
        }
    )
    claims = OpenIDClaims.from_jwt(token)
    assert claims.subject == "subject-123"
    assert claims.email == "Person@Example.com"
    assert claims.nonce == "abc"
    assert claims.issuer == "https://idp.example"


def test_telemetry_shims_are_callable():
    # Whether or not opentelemetry is installed, these must work.
    from dbd.oidc_client.telemetry import meter, tracer

    counter = meter.create_counter(name="t", description="d", unit="{request}")
    with tracer.start_as_current_span("span"):
        counter.add(1, attributes={"outcome": "success"})
