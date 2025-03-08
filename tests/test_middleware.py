import datetime
from unittest.mock import Mock, patch
import time

from django.contrib.auth import get_user_model
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.sessions.backends.db import SessionStore

from django_auth_adfs.middleware import TokenLifecycleMiddleware
from django_auth_adfs.config import settings
from tests.settings import MIDDLEWARE

User = get_user_model()

# Add TokenLifecycleMiddleware to the existing middleware
MIDDLEWARE_WITH_TOKEN_LIFECYCLE = MIDDLEWARE + (
    'django_auth_adfs.middleware.TokenLifecycleMiddleware',
)

@override_settings(MIDDLEWARE=MIDDLEWARE_WITH_TOKEN_LIFECYCLE)
class TokenLifecycleMiddlewareTests(TestCase):
    """
    Tests for the TokenLifecycleMiddleware.
    
    The middleware handles the lifecycle of ADFS tokens:
    1. Storing tokens from user object to session
    2. Detecting when tokens need to be refreshed
    3. Refreshing tokens when needed
    4. Handling OBO (On-Behalf-Of) tokens
    """
    
    def setUp(self):
        """Set up test environment before each test"""
        self.factory = RequestFactory()
        self.middleware = TokenLifecycleMiddleware(lambda r: r)
        self.user = User.objects.create_user(username='testuser')
        self.request = self.factory.get('/')
        self.request.user = self.user
        self.request.session = SessionStore()

    # Group 1: Initialization Tests
    
    def test_init_with_default_settings(self):
        """Test middleware initialization with default settings"""
        middleware = TokenLifecycleMiddleware(lambda r: r)
        self.assertEqual(middleware.threshold, 300)
        self.assertTrue(middleware.store_obo_token)
        self.assertFalse(middleware.using_signed_cookies)
    
    def test_init_with_custom_settings(self):
        """Test middleware initialization with custom settings"""
        with patch('django_auth_adfs.middleware.getattr') as mock_getattr:
            # Mock getattr to return custom values
            mock_getattr.side_effect = lambda obj, name, default: {
                'ADFS_TOKEN_REFRESH_THRESHOLD': 600,
                'ADFS_STORE_OBO_TOKEN': False
            }.get(name, default)
            
            middleware = TokenLifecycleMiddleware(lambda r: r)
            
            # Verify custom settings are applied
            self.assertEqual(middleware.threshold, 600)
            self.assertFalse(middleware.store_obo_token)

    # Group 2: Token Storage Tests
    
    def test_store_tokens_from_user(self):
        """Test storing tokens from user object to session"""
        # Set tokens on user object (in memory only)
        setattr(self.user, 'access_token', "test_access_token")
        setattr(self.user, 'refresh_token', "test_refresh_token")
        setattr(self.user, 'token_expires_at', datetime.datetime.now() + datetime.timedelta(hours=1))
        setattr(self.user, 'obo_access_token', "test_obo_token")
        setattr(self.user, 'obo_token_expires_at', datetime.datetime.now() + datetime.timedelta(hours=1))

        # Call middleware
        self.middleware._store_tokens_from_user(self.request)

        # Check session
        self.assertEqual(self.request.session["ADFS_ACCESS_TOKEN"], "test_access_token")
        self.assertEqual(self.request.session["ADFS_REFRESH_TOKEN"], "test_refresh_token")
        self.assertEqual(self.request.session["ADFS_OBO_ACCESS_TOKEN"], "test_obo_token")
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in self.request.session)
        self.assertTrue("ADFS_OBO_TOKEN_EXPIRES_AT" in self.request.session)
    
    def test_store_partial_tokens_from_user(self):
        """Test storing partial token data (only access token without refresh token)"""
        # Set only access token on user object
        setattr(self.user, 'access_token', "test_access_token")
        setattr(self.user, 'token_expires_at', datetime.datetime.now() + datetime.timedelta(hours=1))
        # No refresh token or OBO token
        
        # Call middleware
        self.middleware._store_tokens_from_user(self.request)
        
        # Check session - should have access token but not refresh token
        self.assertEqual(self.request.session["ADFS_ACCESS_TOKEN"], "test_access_token")
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in self.request.session)
        self.assertFalse("ADFS_REFRESH_TOKEN" in self.request.session)
        self.assertFalse("ADFS_OBO_ACCESS_TOKEN" in self.request.session)

    def test_store_tokens_from_user_with_signed_cookies(self):
        """Test that tokens are not stored when using signed cookies"""
        self.middleware.using_signed_cookies = True
        setattr(self.user, 'access_token', "test_access_token")

        self.middleware._store_tokens_from_user(self.request)
        self.assertFalse("ADFS_ACCESS_TOKEN" in self.request.session)
    
    def test_session_modified_flag(self):
        """Test session.modified is set correctly during token storage operations"""
        # Test 1: When tokens are added, session.modified should be True
        self.request.session.modified = False
        setattr(self.user, 'access_token', "new_token")
        self.middleware._store_tokens_from_user(self.request)
        self.assertTrue(self.request.session.modified)
        
        # Test 2: When no changes are made, session.modified should remain False
        self.request.session.modified = False
        self.middleware._store_tokens_from_user(self.request)
        self.assertFalse(self.request.session.modified)

    # Group 3: Token Refresh Detection Tests
    
    def test_handle_token_refresh_not_needed(self):
        """Test that tokens aren't refreshed if not expired"""
        # Set up a token that doesn't need refresh
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        with patch.object(self.middleware, '_refresh_token') as mock_refresh:
            self.middleware._handle_token_refresh(self.request)
            mock_refresh.assert_not_called()

    def test_handle_token_refresh_needed(self):
        """Test that tokens are refreshed when about to expire"""
        # Set up a token that needs refresh
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=60)  # 1 minute to expiry
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        with patch.object(self.middleware, '_refresh_token') as mock_refresh:
            self.middleware._handle_token_refresh(self.request)
            mock_refresh.assert_called_once_with(self.request)
    
    def test_handle_expired_token(self):
        """Test handling of already expired tokens"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        # Set token as already expired
        expires_at = datetime.datetime.now() - datetime.timedelta(minutes=5)
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        with patch.object(self.middleware, '_refresh_token') as mock_refresh:
            self.middleware._handle_token_refresh(self.request)
            mock_refresh.assert_called_once_with(self.request)
    
    def test_obo_token_expires_before_access_token(self):
        """Test when OBO token expires before access token"""
        # Set up access token with long expiry
        self.request.session["ADFS_ACCESS_TOKEN"] = "access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "refresh_token"
        access_token_expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = access_token_expires_at.isoformat()
        
        # Set up OBO token with short expiry
        self.request.session["ADFS_OBO_ACCESS_TOKEN"] = "obo_token"
        obo_expires_at = datetime.datetime.now() + datetime.timedelta(seconds=30)
        self.request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = obo_expires_at.isoformat()
        
        # Should refresh only OBO token
        with patch.object(self.middleware, '_refresh_token') as mock_refresh_token, \
             patch.object(self.middleware, '_refresh_obo_token') as mock_refresh_obo:
            self.middleware._handle_token_refresh(self.request)
            
            # Verify only OBO token is refreshed, not the access token
            mock_refresh_token.assert_not_called()
            mock_refresh_obo.assert_called_once_with(self.request)
            
            # Verify session state remains unchanged for access token
            self.assertEqual(self.request.session["ADFS_ACCESS_TOKEN"], "access_token")
            self.assertEqual(self.request.session["ADFS_REFRESH_TOKEN"], "refresh_token")
            self.assertEqual(self.request.session["ADFS_TOKEN_EXPIRES_AT"], access_token_expires_at.isoformat())

    # Group 4: Token Refresh Implementation Tests
    
    @patch('django_auth_adfs.middleware.provider_config')
    def test_refresh_token_success(self, mock_provider_config):
        """Test successful token refresh"""
        # Mock the token endpoint response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600
        }
        mock_provider_config.session.post.return_value = mock_response
        mock_provider_config.token_endpoint = "https://example.com/token"

        # Set up initial session state
        self.request.session["ADFS_REFRESH_TOKEN"] = "old_refresh_token"

        # Perform refresh
        self.middleware._refresh_token(self.request)

        # Check session updated
        self.assertEqual(self.request.session["ADFS_ACCESS_TOKEN"], "new_access_token")
        self.assertEqual(self.request.session["ADFS_REFRESH_TOKEN"], "new_refresh_token")
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in self.request.session)
    
    @patch('django_auth_adfs.middleware.provider_config')
    def test_refresh_token_without_new_refresh_token(self, mock_provider_config):
        """Test token refresh when response doesn't include a new refresh token"""
        # Mock the token endpoint response without refresh_token
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "expires_in": 3600
            # No refresh_token in response
        }
        mock_provider_config.session.post.return_value = mock_response
        mock_provider_config.token_endpoint = "https://example.com/token"

        # Set up initial session state
        self.request.session["ADFS_ACCESS_TOKEN"] = "old_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "old_refresh_token"

        # Perform refresh
        self.middleware._refresh_token(self.request)

        # Check session updated correctly
        self.assertEqual(self.request.session["ADFS_ACCESS_TOKEN"], "new_access_token")
        # Old refresh token should be preserved
        self.assertEqual(self.request.session["ADFS_REFRESH_TOKEN"], "old_refresh_token")
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in self.request.session)

    @patch('django_auth_adfs.middleware.provider_config')
    def test_refresh_token_failure(self, mock_provider_config):
        """Test failed token refresh"""
        # Mock the token endpoint response
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid refresh token"
        mock_provider_config.session.post.return_value = mock_response
        mock_provider_config.token_endpoint = "https://example.com/token"

        # Set up initial session state
        self.request.session["ADFS_REFRESH_TOKEN"] = "invalid_refresh_token"
        
        # Store original session state to verify it's not modified
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        # Perform refresh
        self.middleware._refresh_token(self.request)

        # Check session not updated and not modified
        self.assertFalse("ADFS_ACCESS_TOKEN" in self.request.session)
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    def test_refresh_obo_token_success(self):
        """Test successful OBO token refresh"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"

        with patch('django_auth_adfs.backend.AdfsBaseBackend') as mock_backend:
            mock_backend.return_value.get_obo_access_token.return_value = "new_obo_token"
            
            self.middleware._refresh_obo_token(self.request)

            self.assertEqual(self.request.session["ADFS_OBO_ACCESS_TOKEN"], "new_obo_token")
            self.assertTrue("ADFS_OBO_TOKEN_EXPIRES_AT" in self.request.session)

    def test_refresh_obo_token_failure(self):
        """Test failed OBO token refresh"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        
        # Store original session state to verify it's not modified
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        with patch('django_auth_adfs.backend.AdfsBaseBackend') as mock_backend:
            mock_backend.return_value.get_obo_access_token.return_value = None
            
            self.middleware._refresh_obo_token(self.request)

            # Verify session not modified
            self.assertFalse("ADFS_OBO_ACCESS_TOKEN" in self.request.session)
            self.assertEqual(dict(self.request.session), original_session_data)
            self.assertFalse(self.request.session.modified)
    
    def test_obo_token_without_access_token(self):
        """Test OBO token handling when access token is missing"""
        # Only OBO token exists
        self.request.session["ADFS_OBO_ACCESS_TOKEN"] = "obo_token"
        self.request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = datetime.datetime.now().isoformat()
        # No ADFS_ACCESS_TOKEN
        
        # Store original session state to verify it's not modified
        original_session_data = dict(self.request.session)
        self.request.session.modified = False
        
        self.middleware._refresh_obo_token(self.request)
        
        # Verify session not modified
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    # Group 5: Authentication Signal Tests
    
    def test_capture_tokens_from_auth(self):
        """Test capturing tokens during authentication"""
        sender = Mock()
        sender.access_token = "sender_access_token"
        sender.get_obo_access_token.return_value = "obo_token"

        adfs_response = {
            "access_token": "response_access_token",
            "refresh_token": "response_refresh_token",
            "expires_in": 3600
        }

        self.middleware._capture_tokens_from_auth(
            sender=sender,
            user=self.user,
            claims={},
            adfs_response=adfs_response
        )

        # Check user object has temporary token attributes
        self.assertEqual(getattr(self.user, 'access_token'), "sender_access_token")
        self.assertEqual(getattr(self.user, 'refresh_token'), "response_refresh_token")
        self.assertTrue(hasattr(self.user, "token_expires_at"))
        self.assertEqual(getattr(self.user, 'obo_access_token'), "obo_token")
        self.assertTrue(hasattr(self.user, "obo_token_expires_at"))
    
    def test_capture_tokens_from_adfs_response_only(self):
        """Test capturing tokens when they're only in the ADFS response, not on sender"""
        sender = Mock(spec=[])  # Create a mock without access_token attribute
        # Ensure get_obo_access_token is available but returns None
        sender.get_obo_access_token = Mock(return_value=None)

        adfs_response = {
            "access_token": "response_access_token",
            "refresh_token": "response_refresh_token",
            "expires_in": 3600
        }

        self.middleware._capture_tokens_from_auth(
            sender=sender,
            user=self.user,
            claims={},
            adfs_response=adfs_response
        )

        # Check user object has temporary token attributes from adfs_response
        self.assertEqual(getattr(self.user, 'access_token'), "response_access_token")
        self.assertEqual(getattr(self.user, 'refresh_token'), "response_refresh_token")
        self.assertTrue(hasattr(self.user, "token_expires_at"))
        # No OBO token should be set
        self.assertFalse(hasattr(self.user, "obo_access_token"))

    # Group 6: Middleware Call Tests
    
    def test_middleware_call_with_authenticated_user(self):
        """Test the complete middleware request/response cycle with authenticated user"""
        request = self.factory.get('/')
        request.user = self.user
        request.session = SessionStore()

        # Set tokens on user (in memory)
        setattr(self.user, 'access_token', "test_access_token")
        setattr(self.user, 'refresh_token', "test_refresh_token")
        setattr(self.user, 'token_expires_at', datetime.datetime.now() + datetime.timedelta(hours=1))

        with patch.object(self.middleware, '_handle_token_refresh') as mock_refresh:
            response = self.middleware(request)
            
            # Check that tokens were stored and refresh was attempted
            self.assertEqual(request.session["ADFS_ACCESS_TOKEN"], "test_access_token")
            mock_refresh.assert_called_once_with(request)
    
    def test_middleware_post_response_token_storage(self):
        """Test tokens added during view processing are stored after response"""
        # Create a middleware that simulates adding tokens during view processing
        def get_response_with_token_addition(request):
            # Simulate a view that adds tokens to the user
            setattr(request.user, 'access_token', "view_added_token")
            setattr(request.user, 'refresh_token', "view_added_refresh_token")
            setattr(request.user, 'token_expires_at', datetime.datetime.now() + datetime.timedelta(hours=1))
            return request
        
        middleware = TokenLifecycleMiddleware(get_response_with_token_addition)
        
        # Create request
        request = self.factory.get('/')
        request.user = self.user
        request.session = SessionStore()
        
        # Initially, user has no tokens
        self.assertFalse(hasattr(self.user, 'access_token'))
        
        # Process request through middleware
        response = middleware(request)
        
        # Verify tokens were stored in session after view processing
        self.assertEqual(request.session["ADFS_ACCESS_TOKEN"], "view_added_token")
        self.assertEqual(request.session["ADFS_REFRESH_TOKEN"], "view_added_refresh_token")
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in request.session)

    def test_middleware_without_user(self):
        """Test middleware behavior when request has no user"""
        request = self.factory.get('/')
        request.session = SessionStore()

        response = self.middleware(request)
        # Should not raise any errors
        self.assertEqual(response, request)

    def test_middleware_with_unauthenticated_user(self):
        """Test middleware behavior with unauthenticated user"""
        request = self.factory.get('/')
        request.user = Mock(is_authenticated=False)
        request.session = SessionStore()

        with patch.object(self.middleware, '_handle_token_refresh') as mock_refresh:
            response = self.middleware(request)
            mock_refresh.assert_not_called()

    # Group 7: Error Handling Tests
    
    def test_handle_malformed_expiry_time(self):
        """Test handling of malformed expiry time in session"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = "invalid_datetime"
        
        # Store original session state to verify it's not modified inappropriately
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        # Should handle gracefully without error
        self.middleware._handle_token_refresh(self.request)
        
        # Verify session wasn't modified inappropriately
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    def test_handle_incomplete_token_state(self):
        """Test handling when only some token data exists in session"""
        # Only access token, no refresh token
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = datetime.datetime.now().isoformat()
        # Missing ADFS_REFRESH_TOKEN
        
        # Store original session state to verify it's not modified inappropriately
        original_session_data = dict(self.request.session)
        self.request.session.modified = False
        
        self.middleware._handle_token_refresh(self.request)
        
        # Verify session wasn't modified inappropriately
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    def test_handle_malformed_tokens(self):
        """Test handling of malformed/corrupt token data in session"""
        # Invalid token format
        self.request.session["ADFS_ACCESS_TOKEN"] = {"malformed": "data"}
        self.request.session["ADFS_REFRESH_TOKEN"] = None
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = "not-a-date"
        
        # Store original session state to verify it's not modified inappropriately
        original_session_data = dict(self.request.session)
        self.request.session.modified = False
        
        self.middleware._handle_token_refresh(self.request)
        
        # Verify session wasn't modified inappropriately
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)
