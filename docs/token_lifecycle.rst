Token Lifecycle Middleware
========================

Traditionally, django-auth-adfs is used as an authentication solution - it handles user authentication
via ADFS/Azure AD and maps claims to Django users. It doesn't really care about the access tokens from Azure/ADFS after you've been authenticated.
This is a useful pattern for many applications, but for those of you who build internal applications for
your organization, you might want to make delegated API calls to Microsoft Graph or other APIs on behalf of the user.

The Token Lifecycle Middleware extends django-auth-adfs beyond pure authentication to also handle token management
for API access. This creates a more integrated approach where:

* The same application registration handles both authentication and API access
* Tokens obtained during authentication are managed and refreshed automatically
* The application can make delegated API calls on behalf of the user

This middleware is particularly useful for applications that need to make API calls to Microsoft services on behalf of the user, or after the user has been authenticated.
While not required for basic authentication, it represents an architectural decision and whether you need this functionality depends on your specific requirements
and your organization's ADFS/Azure AD configuration.

How it works
-----------

The ``TokenLifecycleMiddleware`` handles the entire token lifecycle:

1. **Initial Token Capture**: Uses a signal handler to capture tokens during authentication
2. **Token Storage**: Automatically stores tokens in the session after successful authentication
3. **Token Refresh**: Checks if the access token is about to expire and refreshes it if needed
4. **Session Management**: Keeps the session updated with the latest tokens
5. **User Object Synchronization**: Ensures the user object has the latest tokens
6. **OBO Token Management**: Handles On-Behalf-Of tokens for Microsoft Graph API

Read more: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow#protocol-diagram

Configuration
------------

To enable the token lifecycle middleware, add it to your ``MIDDLEWARE`` setting in your Django settings file:

.. code-block:: python

    MIDDLEWARE = [
        # ... other middleware
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django_auth_adfs.middleware.TokenLifecycleMiddleware',  # Add this line
        # ... other middleware
    ]

.. important::
    The middleware must be placed after the ``SessionMiddleware`` and ``AuthenticationMiddleware``.


You can configure the token lifecycle behavior with these settings in your Django settings file:

.. code-block:: python

    # Number of seconds before expiration to refresh (default: 300, i.e., 5 minutes)
    ADFS_TOKEN_REFRESH_THRESHOLD = 300

    # Enable or disable OBO token storage for Microsoft Graph API (default: True)
    ADFS_STORE_OBO_TOKEN = True

Azure AD Application Configuration
--------------------------------

When using the Token Lifecycle Middleware, your Azure AD application registration needs additional permissions
beyond those required for simple authentication. This extends the standard authentication-only setup described in the :doc:`azure_ad_config_guide` with additional
API permissions needed for delegated access.

How Token Capture Works
----------------------

The middleware uses Django's signal system to capture tokens during authentication:

1. A signal handler is registered for the ``post_authenticate`` signal
2. When a user is authenticated, the signal handler captures the tokens from the authentication process
3. The middleware then copies these tokens to the session, where they are **persistently stored** until the session expires
4. On subsequent requests, the middleware manages these tokens in the session (refreshing them when needed)

Security Considerations
---------------------

Signed Cookies Session Backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The middleware will not store tokens in the session when using Django's ``signed_cookies`` session backend:

.. code-block:: python

    SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

This is for security reasons:

1. **Size Limitations**: Cookies have size limitations (typically 4KB), which may be exceeded by tokens
2. **Security Risks**: Storing sensitive tokens in cookies increases the risk of token theft
3. **Performance**: Large cookies are sent with every request, increasing bandwidth usage

If you're using the ``signed_cookies`` session backend and need token storage, you must switch to database or cache-based sessions:

.. code-block:: python

    SESSION_ENGINE = 'django.contrib.sessions.backends.db'

.. note::
    This restriction only applies to the ``signed_cookies`` session backend. For other session backends (database, cache, file),
    tokens are stored securely on the server and only a session ID is stored in the cookie.

Understanding Access Tokens vs. OBO Tokens
----------------------------------------

It's important to understand the difference between regular access tokens and OBO (On-Behalf-Of) tokens, especially in the context of delegated access versus application access:

**Delegated Access vs. Application Access**:
    There are two primary ways an application can access resources in Azure AD/ADFS:

    * **Application Access**: The application accesses resources directly with its own identity, not on behalf of a user. This is used for background processes, daemons, or server-to-server scenarios.

    * **Delegated Access**: The application accesses resources on behalf of a signed-in user. The permissions are delegated from the user to the application, and the application operates within the constraints of the user's permissions.

**Regular Access Token**:
    The token obtained during authentication with ADFS. This token is typically scoped to your application and can be used to:

    * Access your own application's resources
    * Access resources that trust your application directly
    * Exchange for an OBO token to access Microsoft Graph API with delegated permissions

**OBO (On-Behalf-Of) Token**:
    A token obtained by exchanging your regular access token. This token is specifically for delegated access to Microsoft Graph API and must be used when:

    * Accessing Microsoft Graph API endpoints (like /me, /users, /groups) on behalf of the user
    * Reading user profile information from Graph with the user's delegated permissions
    * Accessing user's mailbox, calendar, or other Microsoft 365 resources as the user
    * Working with user's groups or organizational data with the user's permissions

The OBO flow is specifically designed for delegated access scenarios where your application needs to access resources (like Microsoft Graph) on behalf of the authenticated user. The middleware handles this exchange automatically when OBO token storage is enabled.

In most ADFS/Azure AD environments, you cannot use the regular access token to directly access Microsoft Graph API for delegated access - you must exchange it for an OBO token. This is because the regular access token is scoped to your application, while the OBO token is scoped to Microsoft Graph API with the user's delegated permissions.

Key Utility Functions
---------------

While the middleware handles most token management automatically, there are a few utility functions you may need to use directly:

Get tokens for API calls
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    # For Microsoft Graph API (requires OBO token)
    from django_auth_adfs.utils import get_obo_access_token

    def graph_api_view(request):
        obo_token = get_obo_access_token(request)
        # Use the OBO token to call Microsoft Graph API...

    # For your own APIs or APIs that accept your application's token
    from django_auth_adfs.utils import get_access_token

    def api_view(request):
        token = get_access_token(request)
        # Use the token to call your API...

Using with Microsoft Graph API
----------------------------

If you need to call Microsoft Graph API, you must use the OBO token:

.. code-block:: python

    from django.contrib.auth.decorators import login_required
    from django.http import JsonResponse
    from django_auth_adfs.utils import get_obo_access_token
    import requests

    @login_required
    def me_view(request):
        """
        Makes a request to the Microsoft Graph API /me endpoint using the OBO token
        """
        # Get the OBO token from the session
        obo_token = get_obo_access_token(request)

        if not obo_token:
            return JsonResponse({"error": "No OBO token available"}, status=401)

        # Make the request to Microsoft Graph API
        headers = {
            "Authorization": f"Bearer {obo_token}",
            "Content-Type": "application/json",
        }

        try:
            # Use the Microsoft Graph API endpoint
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
            response.raise_for_status()  # Raise an exception for 4XX/5XX responses

            # Return the user profile data
            return JsonResponse(response.json())

        except requests.exceptions.RequestException as e:
            # Handle request errors
            return JsonResponse(
                {"error": "Failed to fetch user profile", "details": str(e)}, status=500
            )

Using with External APIs
----------------------

If you need to call an external API that accepts your application's access token, use the regular access token:

.. code-block:: python

    from rest_framework.views import APIView
    from rest_framework.response import Response
    from django_auth_adfs.utils import get_access_token
    import requests

    class ExternalApiView(APIView):
        def get(self, request):
            # Get the access token
            token = get_access_token(request)
            if not token:
                return Response({"error": "No access token available"}, status=401)

            # Use the token to call an external API that accepts your application's token
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get("https://api.example.com/data", headers=headers)

            return Response(response.json())

Considerations
------------

- The middleware will automatically capture and store tokens during authentication using signals.
- You don't need to modify your views or authentication backends to store tokens.
- Token refresh only works for authenticated users.
- If the refresh token is invalid or expired, the middleware will not be able to refresh the access token.
- The middleware will not log the user out if the refresh token is invalid or expired.
- The middleware will not store tokens in the session when using the ``signed_cookies`` session backend by default.
- OBO token storage is enabled by default but can be disabled with the ``ADFS_STORE_OBO_TOKEN`` setting.
- For Microsoft Graph API, always use the OBO token, not the regular access token.
- For your own application's APIs or APIs that directly trust your application, use the regular access token.