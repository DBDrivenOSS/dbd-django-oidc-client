from django.apps import AppConfig


class OidcClientConfig(AppConfig):
    name = "dbd.oidc_client"
    verbose_name = "OpenID Connect Client"
    default_auto_field = "django.db.models.BigAutoField"
