"""
Utility functions for django-auth-adfs.
"""

import datetime
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


def get_token_info(request):
    """
    Get information about the current token from the session.

    Args:
        request: The current request object

    Returns:
        dict: A dictionary containing token information or None if not available
            {
                'access_token': str,
                'refresh_token': str,
                'expires_at': datetime.datetime,
                'is_valid': bool,
                'expires_in': int (seconds)
            }
    """
    if not hasattr(request, "session"):
        return None

    # Don't retrieve tokens from signed_cookies if disabled
    if _is_signed_cookies_disabled():
        logger.debug("Token retrieval from signed_cookies session is disabled")
        return None

    access_token = request.session.get("ADFS_ACCESS_TOKEN")
    refresh_token = request.session.get("ADFS_REFRESH_TOKEN")
    expires_at_str = request.session.get("ADFS_TOKEN_EXPIRES_AT")

    if not access_token:
        return None

    result = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": None,
        "is_valid": True,
        "expires_in": None,
    }

    if expires_at_str:
        try:
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
            result["expires_at"] = expires_at

            # Calculate seconds until expiration
            now = datetime.datetime.now()
            expires_in = (expires_at - now).total_seconds()
            result["expires_in"] = max(0, int(expires_in))

            # Check if token is expired
            result["is_valid"] = expires_in > 0

        except (ValueError, TypeError) as e:
            logger.warning(f"Error parsing token expiration: {e}")

    return result


def get_obo_token_info(request):
    """
    Get information about the current OBO token from the session.

    Args:
        request: The current request object

    Returns:
        dict: A dictionary containing OBO token information or None if not available
            {
                'obo_access_token': str,
                'expires_at': datetime.datetime,
                'is_valid': bool,
                'expires_in': int (seconds)
            }
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

    obo_access_token = request.session.get("ADFS_OBO_ACCESS_TOKEN")
    expires_at_str = request.session.get("ADFS_OBO_TOKEN_EXPIRES_AT")

    if not obo_access_token:
        return None

    result = {
        "obo_access_token": obo_access_token,
        "expires_at": None,
        "is_valid": True,
        "expires_in": None,
    }

    if expires_at_str:
        try:
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
            result["expires_at"] = expires_at

            # Calculate seconds until expiration
            now = datetime.datetime.now()
            expires_in = (expires_at - now).total_seconds()
            result["expires_in"] = max(0, int(expires_in))

            # Check if token is expired
            result["is_valid"] = expires_in > 0

        except (ValueError, TypeError) as e:
            logger.warning(f"Error parsing OBO token expiration: {e}")

    return result


def force_token_refresh(request):
    """
    Force a refresh of the access token.

    Args:
        request: The current request object

    Returns:
        bool: True if the token was refreshed successfully, False otherwise
    """
    if not hasattr(request, "session"):
        return False

    # Don't refresh tokens in signed_cookies if disabled
    if _is_signed_cookies_disabled():
        logger.debug("Token refresh in signed_cookies session is disabled")
        return False

    # Check if we have the necessary session data
    if not all(key in request.session for key in ["ADFS_REFRESH_TOKEN"]):
        return False

    try:
        # Import here to avoid circular imports
        from django_auth_adfs.middleware import TokenLifecycleMiddleware

        # Create a temporary middleware instance
        middleware = TokenLifecycleMiddleware(lambda r: r)

        # Call the refresh method
        middleware._refresh_token(request)

        # Check if the token was refreshed
        return "ADFS_ACCESS_TOKEN" in request.session
    except Exception as e:
        logger.exception(f"Error forcing token refresh: {e}")
        return False


def force_obo_token_refresh(request):
    """
    Force a refresh of the OBO access token for Microsoft Graph API.

    Args:
        request: The current request object

    Returns:
        bool: True if the OBO token was refreshed successfully, False otherwise
    """
    if not hasattr(request, "session"):
        return False

    # Don't refresh tokens in signed_cookies if disabled
    if _is_signed_cookies_disabled():
        logger.debug("Token refresh in signed_cookies session is disabled")
        return False

    # Check if OBO token storage is enabled
    store_obo_token = getattr(settings, "ADFS_STORE_OBO_TOKEN", True)
    if not store_obo_token:
        logger.debug("OBO token storage is disabled")
        return False

    # Check if we have the necessary session data
    if "ADFS_ACCESS_TOKEN" not in request.session:
        return False

    try:
        # Import here to avoid circular imports
        from django_auth_adfs.middleware import TokenLifecycleMiddleware

        # Create a temporary middleware instance
        middleware = TokenLifecycleMiddleware(lambda r: r)

        # Call the refresh method
        middleware._refresh_obo_token(request)

        # Check if the token was refreshed
        return "ADFS_OBO_ACCESS_TOKEN" in request.session
    except Exception as e:
        logger.exception(f"Error forcing OBO token refresh: {e}")
        return False


def sync_user_tokens_from_session(request):
    """
    Synchronize tokens from the session to the user object.

    This is useful if you need to ensure the user object has the latest tokens,
    for example before passing the user object to a function that needs the tokens.

    Args:
        request: The current request object

    Returns:
        bool: True if tokens were synchronized, False otherwise
    """
    if (
        not hasattr(request, "session")
        or not hasattr(request, "user")
        or not request.user.is_authenticated
    ):
        return False

    # Don't sync tokens from signed_cookies if disabled
    if _is_signed_cookies_disabled():
        logger.debug("Token sync from signed_cookies session is disabled")
        return False

    if not all(key in request.session for key in ["ADFS_ACCESS_TOKEN"]):
        return False

    try:
        # Update the user object with tokens from the session
        request.user.access_token = request.session["ADFS_ACCESS_TOKEN"]

        if "ADFS_REFRESH_TOKEN" in request.session:
            request.user.refresh_token = request.session["ADFS_REFRESH_TOKEN"]

        if "ADFS_TOKEN_EXPIRES_AT" in request.session:
            request.user.token_expires_at = datetime.datetime.fromisoformat(
                request.session["ADFS_TOKEN_EXPIRES_AT"]
            )

        # Sync OBO token if available
        store_obo_token = getattr(settings, "ADFS_STORE_OBO_TOKEN", True)
        if store_obo_token:
            if "ADFS_OBO_ACCESS_TOKEN" in request.session:
                request.user.obo_access_token = request.session["ADFS_OBO_ACCESS_TOKEN"]

            if "ADFS_OBO_TOKEN_EXPIRES_AT" in request.session:
                request.user.obo_token_expires_at = datetime.datetime.fromisoformat(
                    request.session["ADFS_OBO_TOKEN_EXPIRES_AT"]
                )

        return True
    except Exception as e:
        logger.exception(f"Error synchronizing tokens from session to user: {e}")
        return False
