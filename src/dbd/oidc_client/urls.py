"""Default URL wiring.

Include with ``include("dbd.oidc_client.urls")`` to get the ``oidc_client:login``,
``oidc_client:callback``, and ``oidc_client:logout`` routes. These use the
email-keyed default user upsert; for provider-specific claim shapes or profile
linking, wire your own view subclasses instead.
"""

from django.urls import path

from dbd.oidc_client.views import (
    BaseOpenIDConnectCallbackView,
    BaseOpenIDConnectLogoutView,
    BaseOpenIDConnectRedirectView,
)

app_name = "oidc_client"

urlpatterns = [
    path("login/", BaseOpenIDConnectRedirectView.as_view(), name="login"),
    path("callback/", BaseOpenIDConnectCallbackView.as_view(), name="callback"),
    path("logout/", BaseOpenIDConnectLogoutView.as_view(), name="logout"),
]
