"""
Utility functions for django-auth-adfs.

Only relevant if you are using the Token Lifecycle Middleware.
"""

import logging

from django_auth_adfs.token_manager import token_manager

logger = logging.getLogger("django_auth_adfs")


def get_access_token(request):
    """
    Get the current access token from the session.

    The token is automatically decrypted before being returned.

    Args:
        request: The current request object

    Returns:
        str: The access token or None if not available
    """
    return token_manager.get_access_token(request)


def get_obo_access_token(request):
    """
    Get the current OBO (On-Behalf-Of) access token for Microsoft Graph API from the session.

    The token is automatically decrypted before being returned.

    Args:
        request: The current request object

    Returns:
        str: The OBO access token or None if not available
    """
    return token_manager.get_obo_access_token(request)


# For backwards compatibility, keep the internal functions
# but make them use the token manager
def _get_encryption_key():
    """
    Derive a Fernet encryption key from Django's SECRET_KEY.

    The salt can be customized through the TOKEN_ENCRYPTION_SALT setting.

    Returns:
        bytes: A 32-byte key suitable for Fernet encryption
    """
    return token_manager._get_encryption_key()


def _encrypt_token(token):
    """
    Encrypt a token using Django's SECRET_KEY.

    Args:
        token (str): The token to encrypt

    Returns:
        str: The encrypted token as a string
    """
    return token_manager.encrypt_token(token)


def _decrypt_token(encrypted_token):
    """
    Decrypt a token that was encrypted using Django's SECRET_KEY.

    Args:
        encrypted_token (str): The encrypted token

    Returns:
        str: The decrypted token or None if decryption fails
    """
    return token_manager.decrypt_token(encrypted_token)


def _is_signed_cookies_disabled():
    """
    Check if token storage is disabled for signed_cookies session backend
    """
    return token_manager.using_signed_cookies
