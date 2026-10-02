"""Errors a sign in can end with.

Every failure the library reports for a sign in that did not finish is an
``OIDCError``, so an application can answer all of them from one place (the
``handle_callback_error`` and ``handle_redirect_error`` view hooks, or one
``except OIDCError``) without importing Authlib, joserfc, or requests.

The classes below are in the order the callback can raise them.

Several of them also inherit from the type that used to leak from the same
place, so an ``except`` clause written against an earlier release keeps working:

* the callback rejections are ``django.core.exceptions.SuspiciousOperation``,
  which Django answers with a 400;
* ``ProviderUnreachable`` is a ``requests.RequestException``, and its
  ``ProviderHTTPError`` subclass is a ``requests.HTTPError``.

The original Authlib, joserfc, or requests error, when there is one, is on
``__cause__``.
"""

import requests
from django.core.exceptions import SuspiciousOperation


class OIDCError(Exception):
    """Root of every error raised for a sign in that did not finish."""


class StateMismatch(OIDCError, SuspiciousOperation):
    """The callback ``state`` matches no pending attempt in this session.

    The attempt is stale (the session expired, or the attempt was evicted or
    already used), or the callback did not come from a sign in this session
    started.
    """


class AuthorizationErrorResponse(OIDCError, SuspiciousOperation):
    """The provider sent ``error`` to the callback in place of ``code``.

    This is the authorization error response of RFC 6749 section 4.1.2.1 and
    OIDC Core section 3.1.2.6. It is raised only for a ``state`` that matches a
    pending attempt, and that attempt is consumed.

    ``error``, ``description``, and ``uri`` are query string text, so anyone can
    write them. They are kept out of ``str()`` and ``repr()`` for that reason.
    Log them if you want them, and never render them.

    Attributes:
        error: The ``error`` code, such as ``access_denied``.
        description: The ``error_description``, or None.
        uri: The ``error_uri``, or None.
    """

    def __init__(self, error: str, description: None | str = None, uri: None | str = None):
        super().__init__("The provider answered the authorization request with an error.")
        self.error = error
        self.description = description
        self.uri = uri


class MissingAuthorizationCode(OIDCError, SuspiciousOperation):
    """The callback matches a pending attempt but has neither ``code`` nor ``error``."""


class ProviderUnreachable(OIDCError, requests.RequestException):
    """The provider gave no usable answer to a discovery, JWKS, or token request.

    Covers a connection that failed or timed out and an answer that is not the
    expected JSON. See ``ProviderHTTPError`` for an HTTP error status.

    Attributes:
        stage: Which call failed: ``"discovery"``, ``"jwks"``, or ``"token"``.
        request: The ``requests`` request, when the original error carried one.
        response: The ``requests`` response, when the original error carried one.
    """

    def __init__(self, stage: str, cause: None | requests.RequestException = None):
        super().__init__(
            f"The provider gave no usable answer to the {stage} request.",
            request=getattr(cause, "request", None),
            response=getattr(cause, "response", None),
        )
        self.stage = stage


class ProviderHTTPError(ProviderUnreachable, requests.HTTPError):
    """The provider answered a discovery, JWKS, or token request with an error status.

    Also a ``requests.HTTPError``, because that is what the token endpoint's 5xx
    answers raised before this hierarchy existed.
    """


class TokenExchangeError(OIDCError):
    """The token endpoint refused the authorization code.

    Attributes:
        error: The provider's error code, such as ``invalid_grant``.
        description: The provider's ``error_description``, or None.
        uri: The provider's ``error_uri``, or None.
    """

    def __init__(self, error: str, description: None | str = None, uri: None | str = None):
        super().__init__(f"The token endpoint refused the authorization code: {error}")
        self.error = error
        self.description = description
        self.uri = uri


class IDTokenValidationError(OIDCError):
    """The token response has no ID token, or its signature or claims are wrong."""


class NonceMismatch(OIDCError, SuspiciousOperation):
    """The ID token ``nonce`` is not the one this attempt sent."""
