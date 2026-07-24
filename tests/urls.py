"""Root URLconf for the test suite.

Mounts the library's default routes so their names resolve under ``reverse()``,
and — just as importantly — gives ``django.shortcuts.redirect`` a URLconf to
consult so a redirect to an absolute external URL (e.g. the provider's
end-session endpoint) raises ``NoReverseMatch`` and falls through to the URL,
rather than failing on a missing ``ROOT_URLCONF``.
"""

from django.urls import include, path

urlpatterns = [
    path("auth/", include("dbd.oidc_client.urls")),
]
