"""Minimal Django settings for the test suite."""

SECRET_KEY = "test-only-not-secret"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "dbd.oidc_client",
]

DATABASES = {
    "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"},
}

CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
}

OIDC_CLIENT = {
    "discovery_url": "https://idp.example/.well-known/openid-configuration",
    "client_id": "test-client",
    "client_secret": "test-secret",
}

USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
