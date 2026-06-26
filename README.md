# dbd-django-oidc-client

[![CI](https://github.com/DBDrivenOSS/dbd-django-oidc-client/actions/workflows/ci.yml/badge.svg)](https://github.com/DBDrivenOSS/dbd-django-oidc-client/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small, reusable OpenID Connect **relying party** for Django. It implements the
authorization-code flow with PKCE, `state`, and `nonce`, and provides class-based
views you subclass per application.

## Design

- **Owns no models.** The library hands you validated claims and a hook; your app
  owns persistence.
- **Engine backed by Authlib + joserfc.** PKCE (S256), the authorization request,
  and the code-for-token exchange use Authlib's `OAuth2Session`. The ID token's
  signature and OIDC claims (`iss`, `aud`, `exp`) are verified with joserfc and
  `CodeIDToken`, with signing algorithms pinned to an asymmetric allowlist.
- **One injectable HTTP session.** Discovery and JWKS calls go through a single
  `requests.Session`, swappable via `OIDC_CLIENT["session"]`.
- **OpenTelemetry is optional.** Install the `otel` extra to record a
  token-exchange counter and span; without it, no-op shims are used.
- **Safe across concurrent tabs.** Logins are isolated by OAuth `state`, so two
  tabs do not clobber each other, and each attempt can be used only once.

## Install

Requires **Python 3.11+** and **Django 4.2+**.

```bash
uv add dbd-django-oidc-client            # or: pip install dbd-django-oidc-client
uv add "dbd-django-oidc-client[otel]"    # with OpenTelemetry
```

## Quick start

```python
# settings.py
INSTALLED_APPS += ["dbd.oidc_client"]

OIDC_CLIENT = {
    "discovery_url": env("OIDC_DISCOVERY_URL"),   # the provider's .well-known URL
    "client_id": env("OIDC_CLIENT_ID"),
    "client_secret": env("OIDC_CLIENT_SECRET"),
    # optional: "session": my_requests_session,
}
```

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    path("auth/", include("dbd.oidc_client.urls")),   # login/ callback/ logout/
]
```

The default callback keys users on **email** and owns no models. To link by
`(issuer, subject)`, override one method:

```python
from dbd.oidc_client.views import BaseOpenIDConnectCallbackView

class CallbackView(BaseOpenIDConnectCallbackView):
    success_url = "home"

    def get_or_create_user_from_claims(self, claims):
        profile, _ = OpenIDProfile.objects.get_or_create(
            issuer=claims.issuer, subject=claims.subject,
            defaults={"user": ...},
        )
        return profile.user
```

## Extension points

| Where | What |
| --- | --- |
| `OIDC_CLIENT` setting | discovery URL, client id/secret, optional `requests.Session` |
| `success_url` | post-login redirect (a `?next=` query param wins over it) |
| `get_or_create_user_from_claims(claims)` | the per-app user upsert |
| `claims_class` | swap in a provider-specific claims dataclass |
| `auth_backend` | the Django auth backend used for `login()` |
| `scopes`, `session_namespace`, `redirect_uri_name` | flow tuning |
| `discovery_url` / `client_id` / `client_secret` (view attrs) | per-view provider override (multi-IdP apps) |
| `get_oauth_client()` | override wholesale for an exotic client |

## Development

```bash
uv sync --extra test
uv run pytest
```

## License

MIT. Copyright (c) 2026 DBDrivenSolutions. See [LICENSE](LICENSE).
