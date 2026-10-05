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

A ``?next=`` on the link that starts a sign in is where the browser goes when
the sign in ends. It comes from the query string, so anyone can write it. The
views keep it and follow it only when it is on this site (see
``is_allowed_next_url``), and fall back to ``success_url`` when it is not.

A sign in that does not finish raises an ``OIDCError`` (see
``dbd.oidc_client.exceptions``). The redirect and callback views pass it to
``handle_redirect_error`` and ``handle_callback_error``, which raise it again
unless a subclass answers with a response of its own.
"""

from __future__ import annotations

import json

from django.contrib.auth import get_user_model, login
from django.contrib.auth import logout as auth_logout
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.generic import RedirectView

from dbd.oidc_client.claims import OpenIDClaims
from dbd.oidc_client.client import OpenIDConnectAuthorizationProvider
from dbd.oidc_client.conf import build_client
from dbd.oidc_client.exceptions import (
    AuthorizationErrorResponse,
    MissingAuthorizationCode,
    NonceMismatch,
    OIDCError,
    StateMismatch,
)

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
    * ``handle_callback_error`` / ``handle_redirect_error`` — answer a sign in
      that did not finish with your own response.
    * ``redirect_uri_name``, ``scopes``, ``session_namespace``.
    * ``success_url_allowed_hosts`` / ``get_success_url_allowed_hosts`` — let a
      ``next`` destination name a host other than this one. Set it on the
      redirect view and on the callback view.
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

    # Hosts, other than the one this request came to, that a ``next`` destination
    # may name. Empty by default, so a sign in can end only on this site.
    success_url_allowed_hosts: set[str] = set()

    # Application data carried with the matched attempt (e.g. ``{"next": ...}``);
    # populated by ``oidc_callback``.
    attempt_extra: None | dict = None

    def get_oauth_client(self) -> OpenIDConnectAuthorizationProvider:
        """Return the OIDC client for this view, built from settings by default."""
        return build_client(
            self.get_redirect_uri(),
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

    def get_success_url_allowed_hosts(self) -> set[str]:
        """Return the hosts a ``next`` destination may name.

        The default is the host this request came to, plus
        ``success_url_allowed_hosts``. The name and the behavior are those of
        Django's ``RedirectURLMixin``.

        Returns:
            The allowed hosts, each with its port when the address has one.
        """
        return {self.request.get_host(), *self.success_url_allowed_hosts}

    def is_allowed_next_url(self, url) -> bool:
        """Tell whether a ``next`` destination may be kept and followed.

        ``next`` comes from the query string, so anyone can write it. It is
        allowed when it is a path on this site, or an address whose host is in
        ``get_success_url_allowed_hosts``. When this request is HTTPS, an
        address that names a scheme must name HTTPS.

        Args:
            url: The candidate destination. A value that is not text is refused.

        Returns:
            True if the browser may be sent to ``url``.
        """
        if not isinstance(url, str):
            return False

        return url_has_allowed_host_and_scheme(
            url,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )

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
                take precedence over any colliding key here. Nothing here is
                checked: the callback view checks ``next`` before it follows it.

        Returns:
            A redirect response to the provider's authorization endpoint.

        Raises:
            ProviderUnreachable: If the discovery document cannot be fetched.
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

        The matched attempt is consumed whatever happens next, so a callback can
        be answered once. That includes a provider error response: the provider
        issued no code, so the attempt is of no further use.

        The state is checked first. An ``error`` that arrives with a state this
        session does not hold raises ``StateMismatch``, not
        ``AuthorizationErrorResponse``, because nothing ties that error to a
        sign in this session started.

        Returns:
            The token response, with ``id_token`` as a validated ``IDToken``.

        Raises:
            StateMismatch: If the state matches no pending attempt.
            AuthorizationErrorResponse: If the provider sent ``error`` in place
                of ``code``. Raised before any call to the provider.
            MissingAuthorizationCode: If the callback has neither ``code`` nor
                ``error``. Raised before any call to the provider.
            ProviderUnreachable: If discovery, the token endpoint, or the JWKS
                endpoint gives no usable answer.
            TokenExchangeError: If the token endpoint refuses the code.
            IDTokenValidationError: If the ID token is missing or not valid.
            NonceMismatch: If the ID token nonce is not the pending nonce.
        """
        params = self.request.GET

        # Match (and consume) the attempt before doing any network work, so a
        # stale or forged state fails fast without a needless token exchange.
        attempt = self._pop_attempt(params.get("state"))
        if attempt is None:
            raise StateMismatch("OAuth state does not match any pending login.")

        error = params.get("error")
        if error is not None:
            raise AuthorizationErrorResponse(
                error,
                description=params.get("error_description"),
                uri=params.get("error_uri"),
            )

        code = params.get("code")
        if not code:
            raise MissingAuthorizationCode("The callback carries no authorization code.")

        client = self.get_oauth_client()
        token_response = client.token(
            code=code,
            request=self.request,
            code_verifier=attempt.get("code_verifier"),
        )

        nonce = attempt.get("nonce")
        claims = json.loads(token_response["id_token"].claims)
        if nonce and nonce != claims.get("nonce"):
            raise NonceMismatch("ID token nonce does not match the pending login nonce.")

        self.attempt_extra = {
            k: v for k, v in attempt.items() if k not in ("code_verifier", "nonce")
        }
        return token_response


class BaseOpenIDConnectRedirectView(OpenIDConnectViewMixin, RedirectView):
    """GET kicks off the flow. A ``?next=`` rides along with that attempt only."""

    def get(self, request, *args, **kwargs) -> HttpResponse:
        """Start the flow, carrying a ``?next=`` on this site with this attempt.

        A ``next`` that ``is_allowed_next_url`` refuses is dropped with no
        error, and the sign in starts without it.
        """
        extra = {}
        next_url = request.GET.get("next")
        if self.is_allowed_next_url(next_url):
            extra["next"] = next_url

        try:
            return self.create_authorize_redirect(**extra)
        except OIDCError as exc:
            return self.handle_redirect_error(exc)

    def handle_redirect_error(self, exc: OIDCError) -> HttpResponse:
        """Answer a sign in that could not start.

        In practice ``exc`` is a ``ProviderUnreachable``: the discovery document
        could not be fetched. The default raises ``exc`` again. Override this to
        return a response of your own, and raise ``exc`` for what you do not
        answer.

        Args:
            exc: The error that stopped the redirect.

        Returns:
            The response to send in place of the redirect to the provider.
        """
        raise exc


class BaseOpenIDConnectCallbackView(OpenIDConnectViewMixin, RedirectView):
    """GET receives the IdP callback, validates it, upserts the user, and logs in.

    The default ``get_or_create_user_from_claims`` keys on email and owns no
    models. Apps that link by ``(issuer, subject)`` via a profile model should
    override it.
    """

    claims_class: type[OpenIDClaims] = OpenIDClaims
    success_url: None | str = None
    auth_backend: str = "django.contrib.auth.backends.ModelBackend"

    def get(self, request, *args, **kwargs) -> HttpResponse:
        """Handle the callback: validate, resolve the user, log in, and redirect.

        An ``OIDCError`` raised on the way to the login goes to
        ``handle_callback_error``.
        """
        try:
            token_response = self.oidc_callback()

            # Keep the raw ID token so the logout view can send it as id_token_hint.
            request.session[ID_TOKEN_HINT_SESSION_KEY] = token_response["id_token"].serialize()

            claims = self.get_claims(token_response)
            user = self.get_or_create_user_from_claims(claims)
            self.login(user)
        except OIDCError as exc:
            return self.handle_callback_error(exc)

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

    def handle_callback_error(self, exc: OIDCError) -> HttpResponse:
        """Answer a sign in that did not finish.

        Receives every ``OIDCError`` raised while the callback is handled: the
        ones ``oidc_callback`` raises, and any subclass that your own overrides
        raise (for example to refuse an account in
        ``get_or_create_user_from_claims``).

        The default raises ``exc`` again, so Django answers 400 for the errors
        that are also a ``SuspiciousOperation`` and 500 for the others. Override
        this to return a response of your own, and raise ``exc`` for what you do
        not answer.

        The ``error``, ``description``, and ``uri`` of an
        ``AuthorizationErrorResponse`` are query string text that anyone can
        write. Never put them in a response.

        Args:
            exc: The error that stopped the sign in.

        Returns:
            The response to send in place of the redirect after login.
        """
        raise exc

    def get_success_url(self, *args, **kwargs) -> str:
        """Return the post-login destination.

        Honors a ``next`` held with this attempt when ``is_allowed_next_url``
        accepts it, and falls back to ``success_url`` when it does not. The
        check is made here as well as in the redirect view, because a session
        can hold a value that was stored with no check.

        ``next`` is returned as it is written. Only ``success_url`` goes
        through ``resolve_url()``, which reads a bare word as a URL name.

        Returns:
            The redirect target.

        Raises:
            ImproperlyConfigured: If the attempt holds no allowed ``next`` and
                ``success_url`` is not set.
        """
        next_url = (self.attempt_extra or {}).get("next")
        if self.is_allowed_next_url(next_url):
            return next_url

        if self.success_url is None:
            raise ImproperlyConfigured(
                "Set `success_url` on the callback view or override get_success_url()."
            )

        return resolve_url(self.success_url)


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
