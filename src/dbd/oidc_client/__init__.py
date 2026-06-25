"""A small, reusable OpenID Connect relying party for Django.

Implements the authorization-code flow with PKCE, state, and nonce, and provides
class-based views to subclass per application. The library owns no models and
treats OpenTelemetry as optional.
"""

__version__ = "0.1.0"
