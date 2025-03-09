"""
Based on https://djangosnippets.org/snippets/1179/
"""

import datetime
import logging
from re import compile

from django.conf import settings as django_settings
from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.urls import reverse

from django_auth_adfs.exceptions import MFARequired
from django_auth_adfs.config import provider_config, settings

LOGIN_EXEMPT_URLS = [
    compile(django_settings.LOGIN_URL.lstrip('/')),
    compile(reverse("django_auth_adfs:login").lstrip('/')),
    compile(reverse("django_auth_adfs:logout").lstrip('/')),
    compile(reverse("django_auth_adfs:callback").lstrip('/')),
]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    LOGIN_EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]

logger = logging.getLogger("django_auth_adfs")


class LoginRequiredMiddleware:
    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        assert hasattr(request, 'user'), "The Login Required middleware requires " \
                                         "authentication middleware to be installed. " \
                                         "Edit your MIDDLEWARE setting to insert " \
                                         "'django.contrib.auth.middleware.AuthenticationMiddleware'. " \
                                         "If that doesn't work, ensure your TEMPLATE_CONTEXT_PROCESSORS " \
                                         "setting includes 'django.core.context_processors.auth'."
        if not request.user.is_authenticated:
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in LOGIN_EXEMPT_URLS):
                try:
                    return redirect_to_login(request.get_full_path())
                except MFARequired:
                    return redirect_to_login('django_auth_adfs:login-force-mfa')

        return self.get_response(request)


class TokenLifecycleMiddleware:
    """
    Middleware that handles the lifecycle of ADFS access and refresh tokens.
    
    This middleware will:
    1. Check if the access token is about to expire
    2. Use the refresh token to get a new access token if needed
    3. Update the tokens in the session
    4. Handle OBO (On-Behalf-Of) tokens for Microsoft Graph API
    
    Token storage during authentication is handled by the backend when this middleware is enabled.
    
    To enable this middleware, add it to your MIDDLEWARE setting:
    'django_auth_adfs.middleware.TokenLifecycleMiddleware'
    
    You can configure the token refresh behavior with these settings:
    
    TOKEN_REFRESH_THRESHOLD: Number of seconds before expiration to refresh (default: 300)
    STORE_OBO_TOKEN: Boolean to enable/disable OBO token storage (default: True)
    LOGOUT_ON_TOKEN_REFRESH_FAILURE: Whether to log out the user if token refresh fails (default: False)
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Default settings
        self.threshold = getattr(settings, "TOKEN_REFRESH_THRESHOLD", 300)
        self.using_signed_cookies = (
            django_settings.SESSION_ENGINE
            == "django.contrib.sessions.backends.signed_cookies"
        )
        self.disable_for_signed_cookies = True
        self.store_obo_token = getattr(settings, "STORE_OBO_TOKEN", True)
        self.logout_on_token_refresh_failure = getattr(settings, "LOGOUT_ON_TOKEN_REFRESH_FAILURE", False)
        if self.using_signed_cookies:
            logger.warning(
                "TokenLifecycleMiddleware is enabled but you are using the signed_cookies session backend. "
                "Storing tokens in signed cookies is not recommended for security reasons and cookie size limitations. "
                "The middleware will not store tokens in the session. "
                "Consider using database or cache-based sessions instead."
            )

    def __call__(self, request):
        if hasattr(request, "user") and request.user.is_authenticated:
            # Only handle token refresh
            self._handle_token_refresh(request)
            
        response = self.get_response(request)
        return response

    def _handle_token_refresh(self, request):
        """
        Check if the access token needs to be refreshed.
        If it does, refresh it.
        """
        try:
            if self.using_signed_cookies:
                return

            if "ADFS_TOKEN_EXPIRES_AT" not in request.session:
                return

            # Check if token is about to expire
            expires_at = datetime.datetime.fromisoformat(request.session["ADFS_TOKEN_EXPIRES_AT"])
            remaining = expires_at - datetime.datetime.now()
            
            if remaining.total_seconds() < self.threshold:
                logger.debug("Token is about to expire. Refreshing...")
                self._refresh_tokens(request)
                
            # Check if OBO token is about to expire
            if self.store_obo_token and "ADFS_OBO_TOKEN_EXPIRES_AT" in request.session:
                obo_expires_at = datetime.datetime.fromisoformat(request.session["ADFS_OBO_TOKEN_EXPIRES_AT"])
                obo_remaining = obo_expires_at - datetime.datetime.now()
                
                if obo_remaining.total_seconds() < self.threshold:
                    logger.debug("OBO token is about to expire. Refreshing...")
                    self._refresh_obo_token(request)
                    
        except Exception as e:
            logger.warning(f"Error checking token expiration: {e}")

    def _refresh_tokens(self, request):
        """
        Refresh the access token using the refresh token
        """
        if self.using_signed_cookies:
            return

        if "ADFS_REFRESH_TOKEN" not in request.session:
            return

        try:
            from django_auth_adfs.utils import _decrypt_token, _encrypt_token

            refresh_token = _decrypt_token(request.session["ADFS_REFRESH_TOKEN"])
            if not refresh_token:
                logger.warning("Failed to decrypt refresh token")
                return

            provider_config.load_config()

            data = {
                "grant_type": "refresh_token",
                "client_id": settings.CLIENT_ID,
                "refresh_token": refresh_token,
            }

            if settings.CLIENT_SECRET:
                data["client_secret"] = settings.CLIENT_SECRET

            # Ensure token_endpoint is a string
            token_endpoint = provider_config.token_endpoint
            if token_endpoint is None:
                logger.error("Token endpoint is None, cannot refresh tokens")
                return False

            response = provider_config.session.post(
                token_endpoint, data=data, timeout=settings.TIMEOUT
            )
            if response.status_code == 200:
                token_data = response.json()
                request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token(
                    token_data["access_token"]
                )
                request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token(
                    token_data["refresh_token"]
                )
                expires_at = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(token_data["expires_in"])
                )
                request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()
                request.session.modified = True
                logger.debug("Refreshed tokens successfully")

                # Also refresh the OBO token if needed
                if self.store_obo_token:
                    self._refresh_obo_token(request)

                return True
            else:
                logger.warning(
                    f"Failed to refresh token: {response.status_code} {response.text}"
                )
                if self.logout_on_token_refresh_failure:
                    logger.info("Logging out user due to token refresh failure")
                    logout(request)

        except Exception as e:
            logger.exception(f"Error refreshing tokens: {e}")
            if self.logout_on_token_refresh_failure:
                logger.info("Logging out user due to token refresh error")
                logout(request)

    def _refresh_obo_token(self, request):
        """
        Refresh the OBO token for Microsoft Graph API
        """
        if not self.store_obo_token:
            return

        if self.using_signed_cookies:
            return

        if "ADFS_ACCESS_TOKEN" not in request.session:
            return

        try:
            provider_config.load_config()

            from django_auth_adfs.utils import _decrypt_token, _encrypt_token

            access_token = _decrypt_token(request.session["ADFS_ACCESS_TOKEN"])
            if not access_token:
                logger.warning("Failed to decrypt access token")
                return

            from django_auth_adfs.backend import AdfsBaseBackend

            backend = AdfsBaseBackend()
            obo_token = backend.get_obo_access_token(access_token)

            if obo_token:
                request.session["ADFS_OBO_ACCESS_TOKEN"] = _encrypt_token(obo_token)
                obo_expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
                request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = obo_expires_at.isoformat()
                request.session.modified = True
                logger.debug("Refreshed OBO token successfully")
                return True

        except Exception as e:
            logger.warning(f"Error refreshing OBO token: {e}")
