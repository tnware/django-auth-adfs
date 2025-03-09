"""
Based on https://djangosnippets.org/snippets/1179/
"""

import datetime
from unittest.mock import Mock, patch
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.sessions.backends.db import SessionStore

from django_auth_adfs.middleware import TokenLifecycleMiddleware
from django_auth_adfs.config import settings as adfs_settings
from django_auth_adfs.utils import (
    get_access_token,
    get_obo_access_token,
    _encrypt_token,
    _decrypt_token,
)
from django_auth_adfs.token_manager import token_manager, TokenManager
from tests.settings import MIDDLEWARE

User = get_user_model()

# Add TokenLifecycleMiddleware to the existing middleware
MIDDLEWARE_WITH_TOKEN_LIFECYCLE = MIDDLEWARE + (
    "django_auth_adfs.middleware.TokenLifecycleMiddleware",
)


@override_settings(MIDDLEWARE=MIDDLEWARE_WITH_TOKEN_LIFECYCLE)
class TokenManagerTests(TestCase):
    """
    Tests for the TokenManager class.

    The TokenManager handles:
    - Token storage during authentication
    - Token encryption/decryption
    - Token refresh
    - Token retrieval
    - OBO token management
    """

    def setUp(self):
        """Set up test environment before each test"""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser")
        self.request = self.factory.get("/")
        self.request.user = self.user
        self.request.session = SessionStore()

    # Group 1: Initialization Tests

    def test_init_with_default_settings(self):
        """Test that the TokenManager initializes with default settings."""
        manager = TokenManager()
        
        # Check default settings
        self.assertEqual(manager.refresh_threshold, 300)
        self.assertTrue(manager.store_obo_token)
        self.assertFalse(manager.logout_on_refresh_failure)

    @override_settings(
        TOKEN_REFRESH_THRESHOLD=600,
        STORE_OBO_TOKEN=False,
        LOGOUT_ON_TOKEN_REFRESH_FAILURE=True,
    )
    def test_init_with_custom_settings(self):
        """Test that the TokenManager initializes with custom settings."""
        # We need to patch the settings module directly since override_settings 
        # doesn't affect already imported modules
        with patch.object(adfs_settings, 'TOKEN_REFRESH_THRESHOLD', 600), \
             patch.object(adfs_settings, 'STORE_OBO_TOKEN', False), \
             patch.object(adfs_settings, 'LOGOUT_ON_TOKEN_REFRESH_FAILURE', True):
            
            manager = TokenManager()
            
            self.assertEqual(manager.refresh_threshold, 600)
            self.assertFalse(manager.store_obo_token)
            self.assertTrue(manager.logout_on_refresh_failure)

    # Group 2: Token Storage Tests

    def test_store_tokens(self):
        """Test storing tokens in session"""
        access_token = "test_access_token"
        refresh_token = "test_refresh_token"
        adfs_response = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 3600
        }

        # Store tokens
        success = token_manager.store_tokens(self.request, access_token, adfs_response)
        self.assertTrue(success)

        # Verify tokens were stored and encrypted
        stored_access = token_manager.get_access_token(self.request)
        self.assertEqual(stored_access, access_token)

        # Check refresh token was stored
        stored_refresh = token_manager.decrypt_token(
            self.request.session[token_manager.REFRESH_TOKEN_KEY]
        )
        self.assertEqual(stored_refresh, refresh_token)

        # Check expiration was stored
        self.assertTrue(token_manager.TOKEN_EXPIRES_AT_KEY in self.request.session)

    def test_store_partial_tokens(self):
        """Test storing only access token without refresh token"""
        access_token = "test_access_token"

        # Store just access token
        success = token_manager.store_tokens(self.request, access_token)
        self.assertTrue(success)

        # Verify access token stored
        stored_access = token_manager.get_access_token(self.request)
        self.assertEqual(stored_access, access_token)

        # Verify no refresh token stored
        self.assertFalse(token_manager.REFRESH_TOKEN_KEY in self.request.session)

    def test_store_tokens_with_signed_cookies(self):
        """Test that tokens are not stored when using signed cookies"""
        # Mock signed cookies setting
        token_manager.using_signed_cookies = True
        try:
            success = token_manager.store_tokens(
                self.request, "test_token", {"refresh_token": "test_refresh"}
            )
            self.assertFalse(success)
            self.assertFalse(token_manager.ACCESS_TOKEN_KEY in self.request.session)
        finally:
            token_manager.using_signed_cookies = False

    # Group 3: Token Encryption Tests

    def test_token_encryption(self):
        """Test token encryption and decryption"""
        original = "test_token"
        encrypted = token_manager.encrypt_token(original)
        decrypted = token_manager.decrypt_token(encrypted)

        self.assertNotEqual(original, encrypted)
        self.assertEqual(original, decrypted)

    @override_settings(TOKEN_ENCRYPTION_SALT="custom-salt-for-testing")
    def test_custom_encryption_salt(self):
        """Test encryption with custom salt"""
        original = "test_token"
        
        # Encrypt with default salt
        default_encrypted = token_manager.encrypt_token(original)
        
        # Encrypt with custom salt
        with patch("django_auth_adfs.token_manager.settings") as mock_settings:
            mock_settings.TOKEN_ENCRYPTION_SALT = "custom-salt-for-testing"
            custom_encrypted = token_manager.encrypt_token(original)
        
        self.assertNotEqual(default_encrypted, custom_encrypted)

    # Group 4: Token Refresh Tests

    def test_check_token_expiration(self):
        """Test token expiration checking"""
        # Set up tokens that will expire soon
        token_manager.store_tokens(
            self.request,
            "test_access",
            {
                "access_token": "test_access",
                "refresh_token": "test_refresh",
                "expires_in": 60  # 1 minute
            }
        )

        # Should detect expiration and attempt refresh
        with patch.object(token_manager, "refresh_tokens") as mock_refresh:
            token_manager.check_token_expiration(self.request)
            mock_refresh.assert_called_once_with(self.request)

    def test_check_token_expiration_not_needed(self):
        """Test token expiration checking when refresh not needed"""
        # Set up tokens that won't expire soon
        token_manager.store_tokens(
            self.request,
            "test_access",
            {
                "access_token": "test_access",
                "refresh_token": "test_refresh",
                "expires_in": 7200  # 2 hours
            }
        )

        # Should not attempt refresh
        with patch.object(token_manager, "refresh_tokens") as mock_refresh:
            token_manager.check_token_expiration(self.request)
            mock_refresh.assert_not_called()

    @patch("django_auth_adfs.token_manager.provider_config")
    def test_refresh_tokens(self, mock_provider_config):
        """Test token refresh process"""
        # Set up expired tokens
        token_manager.store_tokens(
            self.request,
            "old_access",
            {
                "access_token": "old_access",
                "refresh_token": "old_refresh",
                "expires_in": -60  # Expired
            }
        )

        # Mock successful refresh response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access",
            "refresh_token": "new_refresh",
            "expires_in": 3600
        }
        mock_provider_config.session.post.return_value = mock_response
        mock_provider_config.token_endpoint = "https://example.com/token"

        # Attempt refresh
        success = token_manager.refresh_tokens(self.request)
        self.assertTrue(success)

        # Verify tokens were updated
        self.assertEqual(
            token_manager.get_access_token(self.request),
            "new_access"
        )

    # Group 5: OBO Token Tests

    def test_obo_token_management(self):
        """Test OBO token storage and retrieval"""
        # Store regular tokens first
        token_manager.store_tokens(
            self.request,
            "test_access",
            {"access_token": "test_access", "expires_in": 3600}
        )

        # Mock OBO token acquisition
        with patch("django_auth_adfs.backend.AdfsBaseBackend") as mock_backend:
            mock_backend.return_value.get_obo_access_token.return_value = "test_obo"
            
            # Store OBO token
            self.request.session[token_manager.OBO_ACCESS_TOKEN_KEY] = \
                token_manager.encrypt_token("test_obo")
            self.request.session[token_manager.OBO_TOKEN_EXPIRES_AT_KEY] = \
                (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()

        # Verify OBO token retrieval
        obo_token = token_manager.get_obo_access_token(self.request)
        self.assertEqual(obo_token, "test_obo")

    def test_disabled_obo_token(self):
        """Test OBO token functionality when disabled"""
        token_manager.store_obo_token = False
        try:
            # Store regular tokens
            token_manager.store_tokens(
                self.request,
                "test_access",
                {"access_token": "test_access", "expires_in": 3600}
            )

            # Verify no OBO token stored
            self.assertIsNone(token_manager.get_obo_access_token(self.request))
            self.assertFalse(token_manager.OBO_ACCESS_TOKEN_KEY in self.request.session)
        finally:
            token_manager.store_obo_token = True

    # Group 6: Error Handling Tests

    def test_handle_malformed_expiry_time(self):
        """Test handling of malformed expiry time"""
        # Store tokens with invalid expiry
        self.request.session[token_manager.ACCESS_TOKEN_KEY] = \
            token_manager.encrypt_token("test_access")
        self.request.session[token_manager.TOKEN_EXPIRES_AT_KEY] = "invalid_datetime"

        # Should handle gracefully
        success = token_manager.check_token_expiration(self.request)
        self.assertFalse(success)

    def test_handle_encryption_errors(self):
        """Test handling of encryption/decryption errors"""
        # Try to decrypt invalid data
        result = token_manager.decrypt_token("invalid_encrypted_data")
        self.assertIsNone(result)

        # Try to encrypt None
        result = token_manager.encrypt_token(None)
        self.assertIsNone(result)

    @patch("django_auth_adfs.token_manager.provider_config")
    def test_refresh_failure_with_logout(self, mock_provider_config):
        """Test token refresh failure with logout enabled"""
        # Enable logout on refresh failure
        token_manager.logout_on_refresh_failure = True
        try:
            # Set up expired tokens
            token_manager.store_tokens(
                self.request,
                "old_access",
                {
                    "access_token": "old_access",
                    "refresh_token": "old_refresh",
                    "expires_in": -60
                }
            )

            # Mock failed refresh
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.text = "Invalid refresh token"
            mock_provider_config.session.post.return_value = mock_response
            mock_provider_config.token_endpoint = "https://example.com/token"

            # Mock logout
            with patch("django_auth_adfs.token_manager.logout") as mock_logout:
                success = token_manager.refresh_tokens(self.request)
                self.assertFalse(success)
                mock_logout.assert_called_once_with(self.request)
        finally:
            token_manager.logout_on_refresh_failure = False
