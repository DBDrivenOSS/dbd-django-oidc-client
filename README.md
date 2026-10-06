# dbd-django-oidc-client

[![CI](https://github.com/DBDrivenOSS/dbd-django-oidc-client/actions/workflows/ci.yml/badge.svg)](https://github.com/DBDrivenOSS/dbd-django-oidc-client/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/dbd-django-oidc-client.svg)](https://pypi.org/project/dbd-django-oidc-client/) [![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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
- **Refresh grant on the client.** `provider.refresh(refresh_token)` runs the
  `refresh_token` grant against the token endpoint, reusing the same credentials
  and transport. The login flow itself doesn't need it, but apps that keep a
  provider access token alive between API calls do; any returned `id_token` is
  validated like the code exchange, and responses without one pass through.
- **UserInfo on the client.** `provider.userinfo(access_token)` presents a token
  to the provider's userinfo endpoint (OIDC Core §5.3) and returns the claims.
  Relying parties use it for claims the ID token omits; resource servers use it
  to validate opaque access tokens they cannot verify locally, treating a
  non-2xx as rejection.
- **One injectable HTTP session.** Every provider call honors a single
  `requests.Session`, swappable via `OIDC_CLIENT["session"]`. Discovery, JWKS,
  and userinfo use it directly; the token exchange runs through Authlib's own
  `OAuth2Session`, so the library copies that session's transport (mounted adapters plus
  `verify`/`cert`/`proxies`/`trust_env`) onto it. A custom system trust store,
  proxy, or mTLS config thus applies to the token POST too, not just the GETs.
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
| `success_url` | redirect after login (a `?next=` on this site wins over it) |
| `redirect_field_name` | the query parameter that carries the destination, `next` by default (redirect view) |
| `success_url_allowed_hosts` / `get_success_url_allowed_hosts()` | other hosts a `?next=` may name (both views) |
| `get_or_create_user_from_claims(claims)` | the per-app user upsert |
| `claims_class` | swap in a provider-specific claims dataclass |
| `auth_backend` | the Django auth backend used for `login()` |
| `scopes`, `session_namespace`, `redirect_uri_name` | flow tuning |
| `discovery_url` / `client_id` / `client_secret` (view attrs) | per-view provider override (multi-IdP apps) |
| `get_oauth_client()` | override wholesale for an exotic client |
| `handle_callback_error(exc)` | answer a sign in that did not finish (callback view) |
| `handle_redirect_error(exc)` | answer a sign in that could not start (redirect view) |

## The `next` destination

A `?next=` on the login link is where the browser goes when the sign in ends.
The redirect view keeps it with the attempt, and the callback view follows it
in place of `success_url`.

`next` comes from the query string, so anyone can write it. Both views accept
it only when it is on this site: a path, or an address whose host is the host
of the request. When the request is HTTPS, an address that names a scheme must
name HTTPS. A value that fails is dropped with no error, and the sign in ends
at `success_url`. The check is Django's `url_has_allowed_host_and_scheme`, the
one Django's own `LoginView` makes.

What to know:

- **`next` is sent as it is written.** It is never read as a URL name. Only
  `success_url` goes through `resolve_url()`.
- **The callback view checks again.** A session can hold a value that was
  stored with no check, so the callback view does not trust what an attempt
  holds.
- **The parameter name is yours to set.** `redirect_field_name` on the redirect
  view names the query parameter, as on Django's `RedirectURLMixin`. The
  default is `next`. The value is kept with the attempt as
  `attempt_extra["next"]` whatever the parameter is called, so the callback
  view needs no setting. Set it to `None` to carry no destination.
- **Another host is an opt in.** Add it to `success_url_allowed_hosts` on the
  redirect view and on the callback view, or override
  `get_success_url_allowed_hosts()`. The names are those of Django's
  `RedirectURLMixin`.
- **A view of your own owes the same check.** If you override `get()` or
  `get_success_url()` and read `attempt_extra["next"]` yourself, call
  `self.is_allowed_next_url(next_url)` before you redirect there.

```python
class LoginView(BaseOpenIDConnectRedirectView):
    success_url_allowed_hosts = {"reports.example.com"}

class CallbackView(BaseOpenIDConnectCallbackView):
    success_url = "home"
    success_url_allowed_hosts = {"reports.example.com"}
```

## Error handling

Every way a sign in can stop short of a session raises a subclass of
`dbd.oidc_client.exceptions.OIDCError`. You do not need to import Authlib,
joserfc, or requests to catch one.

| Exception | Raised when | Also a |
| --- | --- | --- |
| `StateMismatch` | the callback `state` matches no pending attempt in this session | `SuspiciousOperation` |
| `AuthorizationErrorResponse` | the provider sent `error` in place of `code` (RFC 6749 section 4.1.2.1) | `SuspiciousOperation` |
| `MissingAuthorizationCode` | the callback has neither `code` nor `error` | `SuspiciousOperation` |
| `ProviderUnreachable` | discovery, JWKS, or the token endpoint gave no usable answer | `requests.RequestException` |
| `TokenExchangeError` | the token endpoint refused the code | |
| `IDTokenValidationError` | the ID token is missing, or its signature or claims are wrong | |
| `NonceMismatch` | the ID token `nonce` is not the one this attempt sent | `SuspiciousOperation` |

The table is in the order the callback can raise them. The first three are
raised before any call to the provider.

The callback view passes the error to `handle_callback_error(exc)`, and the
redirect view passes it to `handle_redirect_error(exc)`. Override the hook to
return your own response:

```python
from django.shortcuts import render

from dbd.oidc_client.exceptions import AuthorizationErrorResponse, ProviderUnreachable
from dbd.oidc_client.views import BaseOpenIDConnectCallbackView

class CallbackView(BaseOpenIDConnectCallbackView):
    success_url = "home"

    def handle_callback_error(self, exc):
        if isinstance(exc, AuthorizationErrorResponse) and exc.error == "access_denied":
            return render(self.request, "sso/not_assigned.html", status=403)

        if isinstance(exc, ProviderUnreachable):
            return render(self.request, "sso/try_again.html", status=502)

        raise exc
```

What to know:

- **The default raises the error again.** A view that overrides neither hook
  lets Django answer: 400 for the errors that are also a `SuspiciousOperation`,
  500 for the others. A callback with `error` in it used to end as a 500 from a
  token exchange that had no code to send. It is now a 400, and the provider is
  not called.
- **The provider's error text is not safe to show.** `error`, `description`, and
  `uri` on `AuthorizationErrorResponse` come from the query string, so anyone
  can write them. The library keeps them out of `str(exc)` and builds no
  response from them. Log them if you want them. Never render them.
- **The state is checked first.** An `error` that arrives with a `state` this
  session does not hold raises `StateMismatch`, because nothing ties that error
  to a sign in this session started. When the state does match, the pending
  attempt is consumed, so the same callback cannot be answered twice.
- **Each error says what it knows.** `AuthorizationErrorResponse` and
  `TokenExchangeError` carry `error`, `description`, and `uri`.
  `ProviderUnreachable` carries `stage` (`"discovery"`, `"jwks"`, or `"token"`).
  The original Authlib, joserfc, or requests error is on `__cause__`.
- **Earlier `except` clauses keep working.** `ProviderUnreachable` is still a
  `requests.RequestException`. When the provider answered with an HTTP error
  status it is a `ProviderHTTPError`, which is also a `requests.HTTPError`.
- **Your own refusals can use the same hook.** `handle_callback_error` receives
  every `OIDCError` raised while the callback is handled. Raise your own
  subclass from `get_or_create_user_from_claims` to refuse an account, and
  answer it in the hook.
- **`refresh()` and `userinfo()` are not part of this.** They still raise the
  Authlib, joserfc, and requests errors they raised before.

## Development

```bash
uv sync --extra test
uv run pytest
```

## License

MIT. Copyright (c) 2026 DBDrivenSolutions. See [LICENSE](LICENSE).
