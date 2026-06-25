"""Verify concurrent-tab safety: in-flight attempts are keyed by OAuth ``state``.

Each attempt is stored under its own state, so simultaneous logins in different
tabs do not collide, and an attempt is consumed (single use) on callback. These
tests exercise the per-attempt store directly (no network, no IdP).
"""

from types import SimpleNamespace

import pytest
from django.core.exceptions import SuspiciousOperation

from dbd.oidc_client.views import BaseOpenIDConnectCallbackView, BaseOpenIDConnectRedirectView


class FakeSession(dict):
    """A dict that also tolerates ``session.modified = True``."""

    modified = False


def _view(view_cls, **get_params):
    view = view_cls()
    view.request = SimpleNamespace(session=FakeSession(), GET=dict(get_params))
    return view


def test_concurrent_attempts_do_not_clobber():
    # Two tabs start a login under one shared session.
    view = _view(BaseOpenIDConnectRedirectView)
    view._stash_attempt("stateA", code_verifier="vA", nonce="nA", next="/a/")
    view._stash_attempt("stateB", code_verifier="vB", nonce="nB", next="/b/")

    # Either callback can complete; neither overwrote the other.
    a = view._pop_attempt("stateA")
    b = view._pop_attempt("stateB")
    assert a == {"code_verifier": "vA", "nonce": "nA", "next": "/a/"}
    assert b == {"code_verifier": "vB", "nonce": "nB", "next": "/b/"}


def test_attempt_is_single_use():
    view = _view(BaseOpenIDConnectRedirectView)
    view._stash_attempt("s", code_verifier="v", nonce="n")

    assert view._pop_attempt("s") is not None
    # Replaying the same callback finds nothing the second time.
    assert view._pop_attempt("s") is None


def test_fifo_cap_evicts_oldest_attempts():
    view = _view(BaseOpenIDConnectRedirectView)
    for i in range(view.max_pending_attempts + 2):
        view._stash_attempt(f"s{i}", code_verifier=f"v{i}", nonce=f"n{i}")

    pending = view.request.session[view._pending_key()]
    assert len(pending) == view.max_pending_attempts
    assert "s0" not in pending and "s1" not in pending  # two oldest evicted
    assert "s6" in pending  # newest kept


def test_callback_with_unknown_state_is_rejected():
    # A callback whose state matches no pending attempt fails fast — before any
    # token exchange, so this needs no network.
    view = _view(BaseOpenIDConnectCallbackView, code="abc", state="never-seen")
    with pytest.raises(SuspiciousOperation):
        view.oidc_callback()


def test_session_namespace_isolates_pending_store():
    plain = _view(BaseOpenIDConnectRedirectView)
    assert plain._pending_key() == "oidc_pending"

    namespaced = _view(BaseOpenIDConnectRedirectView)
    namespaced.session_namespace = "vita"
    assert namespaced._pending_key() == "vita_oidc_pending"
