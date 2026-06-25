"""Class-based views for the OIDC authorization-code flow.

Based on AuthGate's class-based OIDC views. Provides:

* ``OpenIDConnectViewMixin`` — the flow plumbing (redirect, per-attempt
  state/nonce/code-verifier session handling, callback validation).
* concrete ``Base*View`` entry points to subclass per application.

The mixin builds its client from the ``OIDC_CLIENT`` setting by default, so a
single-provider app needs no client wiring: set ``success_url`` and, if needed,
override ``get_or_create_user_from_claims``.

Concurrent logins are tab-safe: each in-flight attempt is stored under its own
OAuth ``state``, so simultaneous logins in different tabs do not collide.
"""

from __future__ import annotations

import json

from django.contrib.auth import get_user_model, login
from django.contrib.auth import logout as auth_logout
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse
from django.views.generic import RedirectView

from dbd.oidc_client.claims import OpenIDClaims
from dbd.oidc_client.client import OpenIDConnectAuthorizationProvider
from dbd.oidc_client.conf import build_client

# Session key under which the serialized ID token is stashed for RP-initiated
# logout (``id_token_hint``). Namespaced to avoid colliding with app session data.
ID_TOKEN_HINT_SESSION_KEY = "oidc_id_token_hint"
# Session key holding in-flight authorization attempts, as a dict keyed by the
# OAuth ``state``.
PENDING_ATTEMPTS_SESSION_KEY = "oidc_pending"


class OpenIDConnectViewMixin:
    """Shared plumbing for the authorization-code flow.

    Concurrent-tab safety: each in-flight attempt is stored under its own OAuth
    ``state`` (see ``_stash_attempt``), so simultaneous logins in different tabs
    do not collide and a callback is matched to exactly its own attempt. The
    attempt is consumed on callback, which also blocks replay.

    Override points, in order of how often you'll touch them:

    * ``success_url`` / ``get_or_create_user_from_claims`` — on the callback
      view, the per-app bits.
    * ``redirect_uri_name``, ``scopes``, ``session_namespace``.
    * ``discovery_url`` / ``client_id`` / ``client_secret`` — per-view provider
      overrides (else the ``OIDC_CLIENT`` setting is used).
    * ``get_oauth_client`` — override wholesale for an exotic client.
    """

    redirect_uri_name: str = "oidc_client:callback"
    session_namespace: None | str = None
    scopes: list[str] = ["openid", "email", "profile"]

    # Per-view provider overrides; None falls back to the OIDC_CLIENT setting.
    discovery_url: None | str = None
    client_id: None | str = None
    client_secret: None | str = None

    # Cap on concurrent in-flight attempts kept in the session. Each is tiny (a
    # few short strings); this just stops a user spamming the login link from
    # bloating the session cookie. Oldest attempts are evicted first.
    max_pending_attempts: int = 5

    # Application data carried with the matched attempt (e.g. ``{"next": ...}``);
    # populated by ``oidc_callback``.
    attempt_extra: None | dict = None

    def get_oauth_client(self) -> OpenIDConnectAuthorizationProvider:
        """Return the OIDC client for this view, built from settings by default."""
        return build_client(
            self.get_redirect_uri(),
            self.request,
            discovery_url=self.discovery_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

    def get_redirect_uri(self) -> str:
        """Return the callback URI, resolved from ``redirect_uri_name``."""
        return reverse(self.redirect_uri_name)

    def get_scopes(self) -> list[str]:
        """Return the OAuth scopes to request."""
        return list(self.scopes)

    # ── pending-attempt storage (keyed by OAuth state) ───────────────

    def _pending_key(self) -> str:
        if self.session_namespace:
            return f"{self.session_namespace}_{PENDING_ATTEMPTS_SESSION_KEY}"
        return PENDING_ATTEMPTS_SESSION_KEY

    def _stash_attempt(self, state: str, **data) -> None:
        """Store one in-flight attempt's data under its ``state``.

        Args:
            state: The attempt's OAuth state, used as the key.
            **data: The attempt payload (code verifier, nonce, and any extras).
        """
        pending = self.request.session.get(self._pending_key()) or {}
        pending[state] = data

        # FIFO eviction: dict preserves insertion order, so the first key is oldest.
        while len(pending) > self.max_pending_attempts:
            pending.pop(next(iter(pending)))

        self.request.session[self._pending_key()] = pending
        # Django won't flag the session dirty for an in-place nested-dict mutation.
        self.request.session.modified = True

    def _pop_attempt(self, state: None | str) -> None | dict:
        """Remove and return the attempt for ``state``.

        Args:
            state: The OAuth state returned to the callback.

        Returns:
            The stored attempt payload, or None if no attempt matches.
        """
        pending = self.request.session.get(self._pending_key()) or {}
        attempt = pending.pop(state, None) if state else None

        # Persist the eviction; this is also what blocks callback replay.
        self.request.session[self._pending_key()] = pending
        self.request.session.modified = True
        return attempt

    # ── flow operations ──────────────────────────────────────────────

    def create_authorize_redirect(self, **extra_attempt_data) -> HttpResponseRedirect:
        """Stash this attempt (keyed by ``state``) and redirect to the IdP.

        Args:
            **extra_attempt_data: Application data (e.g. a ``next`` destination)
                persisted with the attempt and returned by ``oidc_callback`` as
                ``attempt_extra``. The protocol values (code verifier, nonce)
                take precedence over any colliding key here.

        Returns:
            A redirect response to the provider's authorization endpoint.
        """
        client = self.get_oauth_client()
        code_verifier = client.generate_code_verifier()
        state = client.generate_state()
        nonce = client.generate_nonce()

        self._stash_attempt(
            state, **{**extra_attempt_data, "code_verifier": code_verifier, "nonce": nonce}
        )

        return client.auth_redirect(
            self.request,
            code_verifier=code_verifier,
            state=state,
            nonce=nonce,
            scope=self.get_scopes(),
        )

    def oidc_callback(self) -> dict:
        """Match the attempt by ``state``, exchange the code, and verify the nonce.

        Sets ``attempt_extra`` to the application data stored alongside the
        matched attempt (an empty dict if none), so a view can resume e.g. a
        ``next`` destination.

        Returns:
            The token response, with ``id_token`` as a validated ``IDToken``.

        Raises:
            SuspiciousOperation: If the state matches no pending attempt, or the
                ID token nonce does not match the pending nonce.
        """
        code = self.request.GET.get("code")
        state = self.request.GET.get("state")

        # Match (and consume) the attempt before doing any network work, so a
        # stale or forged state fails fast without a needless token exchange.
        attempt = self._pop_attempt(state)
        if attempt is None:
            raise SuspiciousOperation("OAuth state does not match any pending login.")

        client = self.get_oauth_client()
        token_response = client.token(
            code=code,
            request=self.request,
            code_verifier=attempt.get("code_verifier"),
        )

        nonce = attempt.get("nonce")
        claims = json.loads(token_response["id_token"].claims)
        if nonce and nonce != claims.get("nonce"):
            raise SuspiciousOperation("ID token nonce does not match the pending login nonce.")

        self.attempt_extra = {
            k: v for k, v in attempt.items() if k not in ("code_verifier", "nonce")
        }
        return token_response


class BaseOpenIDConnectRedirectView(OpenIDConnectViewMixin, RedirectView):
    """GET kicks off the flow. A ``?next=`` rides along with that attempt only."""

    def get(self, request, *args, **kwargs) -> HttpResponseRedirect:
        """Start the flow, carrying any ``?next=`` with this attempt."""
        extra = {}
        if next_url := request.GET.get("next"):
            extra["next"] = next_url

        return self.create_authorize_redirect(**extra)


class BaseOpenIDConnectCallbackView(OpenIDConnectViewMixin, RedirectView):
    """GET receives the IdP callback, validates it, upserts the user, and logs in.

    The default ``get_or_create_user_from_claims`` keys on email and owns no
    models. Apps that link by ``(issuer, subject)`` via a profile model should
    override it.
    """

    claims_class: type[OpenIDClaims] = OpenIDClaims
    success_url: None | str = None
    auth_backend: str = "django.contrib.auth.backends.ModelBackend"

    def get(self, request, *args, **kwargs) -> HttpResponseRedirect:
        """Handle the callback: validate, resolve the user, log in, and redirect."""
        token_response = self.oidc_callback()

        # Keep the raw ID token so the logout view can send it as id_token_hint.
        request.session[ID_TOKEN_HINT_SESSION_KEY] = token_response["id_token"].serialize()

        claims = self.get_claims(token_response)
        user = self.get_or_create_user_from_claims(claims)
        self.login(user)

        return HttpResponseRedirect(self.get_success_url())

    def get_claims(self, token_response: dict) -> OpenIDClaims:
        """Parse the validated ID token into a claims object.

        Args:
            token_response: The token response from ``oidc_callback``.

        Returns:
            The parsed claims, of type ``claims_class``.
        """
        return self.claims_class.from_jwt(token_response["id_token"])

    def get_or_create_user_from_claims(self, claims: OpenIDClaims):
        """Resolve a user by email, creating one if needed.

        This is the model-free default; new users are created with an unusable
        password. Override to link by ``(issuer, subject)`` against an
        application-specific profile model.

        Args:
            claims: The validated ID token claims.

        Returns:
            The resolved or newly created user.
        """
        user_model = get_user_model()
        username_field = user_model.USERNAME_FIELD

        user = user_model._default_manager.filter(email__iexact=claims.email).first()
        if user is None:
            create_kwargs = {"email": claims.email}
            if username_field != "email":
                create_kwargs[username_field] = claims.email
            user = user_model._default_manager.create_user(**create_kwargs)

        return user

    def login(self, user) -> None:
        """Log the user into the current session using ``auth_backend``."""
        login(self.request, user, backend=self.auth_backend)

    def get_success_url(self, *args, **kwargs) -> str:
        """Return the post-login destination.

        Honors a ``?next=`` captured with this attempt, falling back to
        ``success_url``.

        Returns:
            The resolved redirect target.

        Raises:
            ImproperlyConfigured: If neither a ``next`` nor ``success_url`` is set.
        """
        extra = self.attempt_extra or {}
        target = extra.get("next") or self.success_url
        if target is None:
            raise ImproperlyConfigured(
                "Set `success_url` on the callback view or override get_success_url()."
            )
        return resolve_url(target)


class BaseOpenIDConnectLogoutView(OpenIDConnectViewMixin, RedirectView):
    """Local logout, then optionally RP-initiated logout at the provider.

    If the provider advertises an end-session endpoint and a stored
    ``id_token_hint`` is present, the user is bounced through it; otherwise the
    logout is purely local.
    """

    rp_initiated: bool = True
    post_logout_redirect_uri_name: None | str = None
    post_logout_redirect_uri: str = "/"

    def get(self, request, *args, **kwargs) -> HttpResponseRedirect:
        """Log out locally and, if possible, at the provider."""
        id_token_hint = request.session.pop(ID_TOKEN_HINT_SESSION_KEY, None)

        auth_logout(request)

        target = self.get_post_logout_redirect_uri()
        if self.rp_initiated and id_token_hint:
            try:
                return self.get_oauth_client().end_session_redirect(
                    post_logout_redirect_uri=target,
                    id_token_hint=id_token_hint,
                    request=request,
                )
            except ImproperlyConfigured:
                # Provider has no end-session endpoint — fall back to local logout.
                pass

        return HttpResponseRedirect(target)

    def get_post_logout_redirect_uri(self) -> str:
        """Return the absolute URL to return to after logout."""
        if self.post_logout_redirect_uri_name:
            return self.request.build_absolute_uri(reverse(self.post_logout_redirect_uri_name))
        return self.request.build_absolute_uri(self.post_logout_redirect_uri)
