"""Settings access and the default client builder.

A consuming project configures one dict in settings:

    OIDC_CLIENT = {
        "discovery_url": "https://idp.example/.well-known/openid-configuration",
        "client_id": env("OIDC_CLIENT_ID"),
        "client_secret": env("OIDC_CLIENT_SECRET"),
        # optional: "session": <requests.Session>,
    }

Views build their client through ``build_client``, which reads this dict.
Per-view overrides (for apps talking to more than one provider) are supported by
passing explicit arguments or setting the corresponding view attributes.
"""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from dbd.oidc_client.client import OpenIDConfiguration, OpenIDConnectAuthorizationProvider

SETTINGS_KEY = "OIDC_CLIENT"


def get_config() -> dict:
    """Return the ``OIDC_CLIENT`` settings dict.

    Returns:
        The configured settings dict.

    Raises:
        ImproperlyConfigured: If the setting is missing or empty.
    """
    config = getattr(settings, SETTINGS_KEY, None)
    if not config:
        raise ImproperlyConfigured(
            f"The {SETTINGS_KEY} setting is required by dbd-django-oidc-client."
        )
    return config


def _resolve(name: str, override, *, required: bool = True):
    """Return ``override`` if given, otherwise the configured value for ``name``."""
    value = override if override is not None else get_config().get(name)
    if required and not value:
        raise ImproperlyConfigured(f"{SETTINGS_KEY}['{name}'] is required (or pass it explicitly).")
    return value


def build_client(
    redirect_uri: str,
    request=None,
    *,
    discovery_url: None | str = None,
    client_id: None | str = None,
    client_secret: None | str = None,
) -> OpenIDConnectAuthorizationProvider:
    """Construct a provider client from settings, with optional per-call overrides.

    Args:
        redirect_uri: The callback URI for this flow.
        request: The current request, used to absolutize a relative redirect URI.
        discovery_url: Overrides ``OIDC_CLIENT["discovery_url"]``.
        client_id: Overrides ``OIDC_CLIENT["client_id"]``.
        client_secret: Overrides ``OIDC_CLIENT["client_secret"]``.

    Returns:
        A configured client.

    Raises:
        ImproperlyConfigured: If a required value is neither passed nor configured.
    """
    discovery_url = _resolve("discovery_url", discovery_url)
    client_id = _resolve("client_id", client_id)
    client_secret = _resolve("client_secret", client_secret)

    configuration = OpenIDConfiguration.from_config_url(discovery_url)

    return OpenIDConnectAuthorizationProvider(
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
        open_id_configuration=configuration,
    )
