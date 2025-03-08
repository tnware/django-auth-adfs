Token Lifecycle Middleware
========================

Traditionally, django-auth-adfs is used **exclusively** as an authentication solution - it handles user authentication
via ADFS/Azure AD and maps claims to Django users. It doesn't really care about the access tokens from Azure/ADFS after you've been authenticated.
This is a useful pattern for many applications, but for those of you who build internal applications for
your organization, you might want to make delegated requests to Microsoft Graph or other resources on behalf of the user.

The Token Lifecycle Middleware extends django-auth-adfs beyond pure authentication to also handle the complete lifecycle of access tokens
after the authentication process. This creates a more integrated approach where:

* The same application registration handles both authentication and API access
* Tokens obtained during authentication are managed and refreshed automatically
* The application can make delegated API calls on behalf of the user

This middleware is particularly useful for applications that need to make delegated requests to Microsoft services on behalf of the user, or otherwise make additional
requests to the Azure AD/ADFS application after the user has been authenticated.

While not required for basic authentication, it represents an architectural decision and whether you need this functionality depends on your specific requirements
and your organization's ADFS/Azure AD configuration.

How it works
-----------

The ``TokenLifecycleMiddleware`` handles the entire token lifecycle:

1. **Initial Token Capture**: Uses the ``post_authenticate`` signal to capture tokens during authentication
2. **Token Storage**: Automatically stores tokens in the users session after successful authentication
3. **Token Refresh**: Checks if the access token is about to expire and refreshes it if needed
4. **Session Management**: Keeps the session updated with the latest tokens
5. **OBO Token Management**: Handles On-Behalf-Of tokens for Microsoft Graph API

Read more: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow#protocol-diagram


.. warning::
    The Token Lifecycle Middleware is a new feature in django-auth-adfs and is considered experimental.
    Please be aware:

    **Currently no community support is guaranteed to be available for this feature**

    We recommend thoroughly testing this feature in your specific environment before deploying to production.

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

.. important::
    Your Django application's session cookie age must be set to a value that is less than that of your ADFS/Azure AD application's refresh token lifetime.

    If a users refresh token has expired, the user will be required to re-authenticate to continue making delegated requests.

Security Considerations
---------------------

Signed Cookies Session Backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The middleware will not store tokens in the session when using Django's ``signed_cookies`` session backend:

.. code-block:: python

    # This will not work with the token lifecycle middleware
    SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

This is for security reasons:

1. **Size Limitations**: Cookies have size limitations (typically 4KB), which may be exceeded by tokens
2. **Security Risks**: Storing sensitive tokens in cookies increases the risk of token theft
3. **Performance**: Large cookies are sent with every request, increasing bandwidth usage

If you're using the ``signed_cookies`` session backend and need token storage, you wont be able to use the token lifecycle middleware.

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
    The OBO flow is specifically designed for delegated access scenarios where your application needs to access resources (like Microsoft Graph) on behalf of the authenticated user. The middleware handles this exchange automatically when OBO token storage is enabled.

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

Accessing Tokens in Your Views
-----------------------------

When building views that need to make API calls, you'll need to access the tokens stored in the session.

Django-auth-adfs provides utility functions in the ``django_auth_adfs.utils`` module to help you access tokens safely.

.. code-block:: python

    # For your own APIs or APIs that trust your application directly
    from django_auth_adfs.utils import get_access_token

    # For Microsoft Graph API or other APIs requiring delegated access
    from django_auth_adfs.utils import get_obo_access_token


You could also directly access tokens from the session:

.. code-block:: python

    # Not recommended - lacks security checks and configuration awareness
    access_token = request.session.get("ADFS_ACCESS_TOKEN")
    obo_token = request.session.get("ADFS_OBO_ACCESS_TOKEN")


Examples
----------------------

Here are practical examples of using these utility functions in your views:

Using with Microsoft Graph API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from django.contrib.auth.decorators import login_required
    from django.http import JsonResponse
    from django_auth_adfs.utils import get_obo_access_token
    import requests

    @login_required
    def me_view(request):
        """Get the user's profile from Microsoft Graph API"""
        obo_token = get_obo_access_token(request)

        if not obo_token:
            return JsonResponse({"error": "No OBO token available"}, status=401)

        headers = {
            "Authorization": f"Bearer {obo_token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
            response.raise_for_status()
            return JsonResponse(response.json())
        except requests.exceptions.RequestException as e:
            return JsonResponse(
                {"error": "Failed to fetch user profile", "details": str(e)},
                status=500
            )

Using with other resources
~~~~~~~~~~~~~~~~~~~~~~~

The key difference is to use the get_access_token function to get the token for the resource you are accessing.

This is different than the get_obo_access_token function, which is used for Microsoft Graph API delegated access in the previous example.

.. code-block:: python

    from rest_framework.views import APIView
    from rest_framework.response import Response
    from django_auth_adfs.utils import get_access_token
    import requests

    class ExternalApiView(APIView):
        def get(self, request):
            """Call an API that accepts your application's token"""
            token = get_access_token(request)

            if not token:
                return Response({"error": "No access token available"}, status=401)

            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get("https://api.example.com/data", headers=headers)

            return Response(response.json())