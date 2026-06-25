"""Validated ID-token claim containers.

Kept free of Django imports so claim parsing is cheap to unit test. Providers
with a richer claim shape subclass ``OpenIDClaims``.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class OpenIDClaims:
    """The minimum set of claims this library relies on."""

    audience: str
    expires: datetime
    issuer: str
    issued_at: datetime
    subject: str
    # email is not strictly required by OpenID, but it is the default user key.
    email: str
    nonce: None | str = None

    @classmethod
    def from_jwt(cls, token) -> "OpenIDClaims":
        """Build an instance from a validated ID token.

        Args:
            token: A validated ID token exposing its claims as a JSON string on
                ``token.claims``.

        Returns:
            The parsed claims.
        """
        data = json.loads(token.claims)
        return cls(
            audience=data["aud"],
            expires=datetime.fromtimestamp(data["exp"], tz=UTC),
            issuer=data["iss"],
            issued_at=datetime.fromtimestamp(data["iat"], tz=UTC),
            subject=data["sub"],
            email=data["email"],
            nonce=data.get("nonce"),
        )
