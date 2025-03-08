"""
Utility functions for django-auth-adfs.

Only relevant if you are using the Token Lifecycle Middleware.
"""

import logging

from django.conf import settings as django_settings
from django_auth_adfs.config import settings

logger = logging.getLogger("django_auth_adfs")


def _is_signed_cookies_disabled():
    """
    Check if token storage is disabled for signed_cookies session backend
    """
    using_signed_cookies = (
        django_settings.SESSION_ENGINE
        == "django.contrib.sessions.backends.signed_cookies"
    )
    # Always disable token storage for signed_cookies for security reasons
    return using_signed_cookies


def get_access_token(request):
    """
    Get the current access token from the session.

    Args:
        request: The current request object

    Returns:
        str: The access token or None if not available
    """
    if not hasattr(request, "session"):
        return None

    # Don't retrieve tokens from signed_cookies if disabled
    if _is_signed_cookies_disabled():
        logger.debug("Token retrieval from signed_cookies session is disabled")
        return None

    return request.session.get("ADFS_ACCESS_TOKEN")


def get_obo_access_token(request):
    """
    Get the current OBO (On-Behalf-Of) access token for Microsoft Graph API from the session.

    Args:
        request: The current request object

    Returns:
        str: The OBO access token or None if not available
    """
    if not hasattr(request, "session"):
        return None

    # Don't retrieve tokens from signed_cookies if disabled
    if _is_signed_cookies_disabled():
        logger.debug("Token retrieval from signed_cookies session is disabled")
        return None

    # Check if OBO token storage is enabled
    store_obo_token = getattr(settings, "ADFS_STORE_OBO_TOKEN", True)
    if not store_obo_token:
        logger.debug("OBO token storage is disabled")
        return None

    return request.session.get("ADFS_OBO_ACCESS_TOKEN")
