"""OpenID Connect relying-party engine.

Provides two pieces:

* ``OpenIDConfiguration`` — provider metadata (endpoints, issuer) plus JWKS
  loading, built from a discovery document or its ``.well-known`` URL.
* ``OpenIDConnectAuthorizationProvider`` — a client bound to one provider
  configuration and redirect URI that drives the authorization-code flow.

The protocol mechanics are delegated to Authlib and its JOSE companion joserfc:
PKCE (S256), the authorization request, and the code-for-token exchange use
Authlib's ``OAuth2Session``; ``validate_id_token`` verifies the ID token's
signature and its OIDC claims (``iss``, ``aud`` including the ``azp`` rule, and
``exp``) with joserfc and ``CodeIDToken``. Signing algorithms are pinned to an
asymmetric allowlist, so ``alg`` confusion (an HS256 token verified against an
RSA key, or ``alg=none``) is rejected.

Discovery and JWKS fetches go through ``dbd.oidc_client.http.get_session`` (swap via
``OIDC_CLIENT["session"]``); OpenTelemetry is optional.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urlencode, urlparse

from authlib.common.security import generate_token
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oidc.core import CodeIDToken
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from joserfc import jwt
from joserfc.jwk import KeySet

from dbd.oidc_client.http import get_session
from dbd.oidc_client.telemetry import meter, tracer

_CONFIG_CACHE_PREFIX = "oidc-config:"
_JWKS_CACHE_PREFIX = "oidc-jwks:"
# Clock-skew tolerance (seconds) when validating the id_token's time claims.
_LEEWAY = 120
# Asymmetric signing algorithms accepted for id_tokens. Pinning this rejects
# alg-confusion / "none" attacks.
_ALLOWED_ALGORITHMS = [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
]

token_exchange_counter = meter.create_counter(
    name="oauth_token_exchange_requests_total",
    description="Total OAuth token exchange requests by outcome",
    unit="{request}",
)


def _is_absolute_uri(uri: str) -> bool:
    return bool(urlparse(uri).netloc)


class IDToken:
    """A validated ID token passed from the engine to the view layer.

    The signature and claims have already been verified. The claims are exposed
    as a JSON string on ``claims`` and the raw compact JWT via ``serialize()``.
    """

    __slots__ = ("_raw", "_claims")

    def __init__(self, raw: str, claims: dict):
        self._raw = raw
        self._claims = claims

    @property
    def claims(self) -> str:
        """The validated claims, encoded as a JSON string."""
        return json.dumps(self._claims)

    def serialize(self) -> str:
        """Return the raw compact JWT."""
        return self._raw


@dataclass
class OpenIDConfiguration:
    """The subset of a provider's discovery document this client uses."""

    authorization_endpoint: str
    token_endpoint: str
    issuer: None | str = None
    revocation_endpoint: None | str = None
    userinfo_endpoint: None | str = None
    jwks_uri: None | str = None
    end_session_endpoint: None | str = None
    scopes_supported: None | list[str] = None
    discovery_url: None | str = None

    @classmethod
    def from_config(cls, discovery_document: dict, *, discovery_url: None | str = None):
        """Build a configuration from an already-fetched discovery document.

        Args:
            discovery_document: The provider's parsed OpenID discovery document.
            discovery_url: The URL the document was fetched from, retained so the
                cached entry can be refreshed later.

        Returns:
            The provider configuration.
        """
        return cls(
            authorization_endpoint=discovery_document["authorization_endpoint"],
            token_endpoint=discovery_document["token_endpoint"],
            issuer=discovery_document.get("issuer"),
            revocation_endpoint=discovery_document.get("revocation_endpoint"),
            userinfo_endpoint=discovery_document.get("userinfo_endpoint"),
            jwks_uri=discovery_document.get("jwks_uri"),
            end_session_endpoint=discovery_document.get("end_session_endpoint"),
            scopes_supported=discovery_document.get("scopes_supported"),
            discovery_url=discovery_url,
        )

    @classmethod
    def from_config_url(cls, discovery_url: str, *, timeout: int = 60 * 10):
        """Build and cache a configuration from a discovery URL.

        Args:
            discovery_url: An absolute URL to the provider's
                ``.well-known/openid-configuration`` document.
            timeout: Cache lifetime in seconds.

        Returns:
            The provider configuration, served from cache when available.

        Raises:
            ValueError: If ``discovery_url`` is not absolute.
        """
        if not _is_absolute_uri(discovery_url):
            raise ValueError(f"discovery_url must be absolute, got {discovery_url!r}")

        return cache.get_or_set(
            f"{_CONFIG_CACHE_PREFIX}{discovery_url}",
            default=lambda: cls.from_config(
                get_session().get(discovery_url).json(),
                discovery_url=discovery_url,
            ),
            timeout=timeout,
        )

    def refresh_cache(self):
        """Drop the cached configuration and re-fetch the discovery document.

        Returns:
            A freshly fetched configuration.

        Raises:
            AssertionError: If this configuration was not built from a discovery URL.
        """
        if not self.discovery_url:
            raise AssertionError("Cannot refresh a config that was not built from a discovery_url.")

        cache.delete(f"{_CONFIG_CACHE_PREFIX}{self.discovery_url}")
        return self.from_config_url(self.discovery_url)

    def load_jwks(self) -> KeySet:
        """Return the provider's JWKS as a key set, fetching and caching it.

        Returns:
            The provider's JSON Web Key Set.

        Raises:
            ImproperlyConfigured: If the configuration has no ``jwks_uri``.
        """
        if not self.jwks_uri:
            raise ImproperlyConfigured("Provider configuration has no jwks_uri.")

        raw = cache.get_or_set(
            f"{_JWKS_CACHE_PREFIX}{self.jwks_uri}",
            default=lambda: get_session().get(self.jwks_uri).json(),
            timeout=60 * 60,
        )
        return KeySet.import_key_set(raw)

    def refresh_jwks(self) -> KeySet:
        """Drop the cached JWKS and re-fetch it.

        Used when the provider rotates its signing keys.

        Returns:
            The freshly fetched key set.
        """
        cache.delete(f"{_JWKS_CACHE_PREFIX}{self.jwks_uri}")
        return self.load_jwks()


class OpenIDConnectAuthorizationProvider:
    """A relying-party client bound to one provider configuration and redirect URI."""

    def __init__(
        self,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        open_id_configuration: OpenIDConfiguration,
    ):
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret
        self.open_id_configuration = open_id_configuration

    def _session(self, redirect_uri: str) -> OAuth2Session:
        return OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=redirect_uri,
            code_challenge_method="S256",
        )

    def auth_redirect(
        self,
        request=None,
        code_verifier: str = None,
        nonce: str = None,
        state: str = None,
        scope=None,
    ) -> HttpResponseRedirect:
        """Build the authorization request URL (with PKCE) and redirect to the IdP.

        Args:
            request: The current request, used to absolutize a relative redirect URI.
            code_verifier: The PKCE code verifier; its S256 challenge is sent.
            nonce: The OIDC nonce to bind into the ID token.
            state: The opaque state used to correlate the callback.
            scope: Requested scopes, as a list or a space-delimited string.

        Returns:
            A redirect response to the provider's authorization endpoint.
        """
        scope = scope or self.open_id_configuration.scopes_supported or ["openid", "email"]
        if isinstance(scope, (list, tuple)):
            scope = " ".join(scope)

        redirect_uri = self.insure_absolute_redirect(self.redirect_uri, request=request)
        session = self._session(redirect_uri)

        extra = {}
        if nonce:
            extra["nonce"] = nonce

        uri, _ = session.create_authorization_url(
            self.open_id_configuration.authorization_endpoint,
            code_verifier=code_verifier,
            state=state,
            scope=scope,
            **extra,
        )
        return redirect(uri)

    def token(self, code: str, request=None, code_verifier: str = None) -> dict:
        """Exchange the authorization code for tokens and validate the ID token.

        Args:
            code: The authorization code returned to the callback.
            request: The current request, used to absolutize a relative redirect URI.
            code_verifier: The PKCE code verifier from the authorization step.

        Returns:
            The token response, with ``id_token`` replaced by a validated
            ``IDToken``.
        """
        redirect_uri = self.insure_absolute_redirect(self.redirect_uri, request=request)
        session = self._session(redirect_uri)

        with tracer.start_as_current_span("oidc.token_exchange"):
            try:
                token_response = session.fetch_token(
                    self.open_id_configuration.token_endpoint,
                    grant_type="authorization_code",
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                )
            except Exception:
                token_exchange_counter.add(1, attributes={"outcome": "failure"})
                raise
            else:
                token_exchange_counter.add(1, attributes={"outcome": "success"})

        token_response = dict(token_response)

        raw_id_token = token_response["id_token"]
        claims = self.validate_id_token(raw_id_token)
        token_response["id_token"] = IDToken(raw_id_token, dict(claims))
        return token_response

    def validate_id_token(self, raw_id_token: str) -> CodeIDToken:
        """Verify an ID token's signature and OIDC claims.

        Validates the signature against the provider JWKS and checks ``iss``,
        ``aud`` (including the ``azp`` rule) and ``exp``. On a signature or key
        failure the JWKS is refreshed once (to cover key rotation) and the
        verification is retried.

        Args:
            raw_id_token: The compact ID token JWT.

        Returns:
            The validated claims.
        """
        try:
            token = jwt.decode(
                raw_id_token, self.open_id_configuration.load_jwks(), algorithms=_ALLOWED_ALGORITHMS
            )
        except Exception:
            token = jwt.decode(
                raw_id_token,
                self.open_id_configuration.refresh_jwks(),
                algorithms=_ALLOWED_ALGORITHMS,
            )

        options = None
        if self.open_id_configuration.issuer:
            options = {"iss": {"essential": True, "value": self.open_id_configuration.issuer}}

        claims = CodeIDToken(
            token.claims, token.header, options=options, params={"client_id": self.client_id}
        )
        claims.validate(leeway=_LEEWAY)
        return claims

    def end_session_redirect(
        self,
        post_logout_redirect_uri: None | str = None,
        id_token_hint: None | str = None,
        request=None,
    ) -> HttpResponseRedirect:
        """Redirect to the provider's end-session endpoint (RP-initiated logout).

        Args:
            post_logout_redirect_uri: Where the provider should return the user.
            id_token_hint: The serialized ID token identifying the session.
            request: The current request, used to absolutize a relative URI.

        Returns:
            A redirect response to the end-session endpoint.

        Raises:
            ImproperlyConfigured: If the provider has no end-session endpoint.
        """
        endpoint = self.open_id_configuration.end_session_endpoint
        if not endpoint:
            raise ImproperlyConfigured("Provider does not advertise an end_session_endpoint.")

        params = {"client_id": self.client_id}
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = self.insure_absolute_redirect(
                post_logout_redirect_uri, request=request
            )
        if id_token_hint:
            params["id_token_hint"] = id_token_hint

        return redirect(f"{endpoint}?{urlencode(params)}")

    @staticmethod
    def insure_absolute_redirect(redirect_uri, request=None):
        """Return an absolute redirect URI, building one from the request if needed.

        Args:
            redirect_uri: An absolute URI, or a relative one to absolutize.
            request: The current request, required when ``redirect_uri`` is relative.

        Returns:
            An absolute redirect URI.

        Raises:
            ImproperlyConfigured: If ``redirect_uri`` is relative and no request
                was supplied.
        """
        if OpenIDConnectAuthorizationProvider.is_absolute_uri(redirect_uri):
            return redirect_uri

        if not request:
            raise ImproperlyConfigured(
                "redirect_uri is a relative path and request is None. Cannot build an absolute uri!"
            )

        return request.build_absolute_uri(redirect_uri)

    @staticmethod
    def is_absolute_uri(uri: str) -> bool:
        """Return whether ``uri`` is absolute (has a network location)."""
        return _is_absolute_uri(uri)

    @staticmethod
    def generate_code_verifier() -> str:
        """Return a new PKCE code verifier."""
        # A 48-character URL-safe token, within PKCE's required 43-128 range.
        return generate_token(48)

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Return the S256 PKCE challenge for ``code_verifier``."""
        return create_s256_code_challenge(code_verifier)

    @staticmethod
    def generate_nonce() -> str:
        """Return a new OIDC nonce."""
        return generate_token(20)

    @staticmethod
    def generate_state() -> str:
        """Return a new OAuth state token."""
        return generate_token(32)
