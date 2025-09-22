from django.contrib.auth.middleware import get_user
from django.contrib.auth.models import AnonymousUser
from django.utils.functional import SimpleLazyObject
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken


class CookieJWTAuthenticationMiddleware:
    """
    Custom middleware that authenticates users based on JWT tokens stored in httpOnly cookies.
    This middleware runs before the standard Django authentication middleware.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract token from cookie
        access_token = request.COOKIES.get('access_token')

        if access_token:
            try:
                # Validate the token
                validated_token = AccessToken(access_token)
                user_id = validated_token['user_id']

                # Get the user
                from django.contrib.auth.models import User
                try:
                    user = User.objects.get(id=user_id)
                    # Set the user on the request
                    request.user = user
                except User.DoesNotExist:
                    request.user = AnonymousUser()

            except (InvalidToken, TokenError, KeyError):
                # Token is invalid, set anonymous user
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

        response = self.get_response(request)
        return response


class CookieJWTRefreshMiddleware:
    """
    Middleware that automatically refreshes access tokens when they expire.
    This should run after CookieJWTAuthenticationMiddleware.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Check if the user is authenticated and if there was an auth error
        if (hasattr(request, 'user') and
            request.user and
            not request.user.is_anonymous and
            hasattr(response, 'status_code') and
            response.status_code == 401):

            # Try to refresh the token
            refresh_token = request.COOKIES.get('refresh_token')
            if refresh_token:
                try:
                    from rest_framework_simplejwt.tokens import RefreshToken
                    refresh = RefreshToken(refresh_token)
                    new_access_token = str(refresh.access_token)

                    # Set new access token cookie
                    from django.conf import settings
                    is_production = not settings.DEBUG

                    response.set_cookie(
                        key='access_token',
                        value=new_access_token,
                        httponly=True,
                        secure=is_production,  # Secure in production (HTTPS required)
                        samesite='Strict',
                        max_age=300  # 5 minutes
                    )

                    # Update response to indicate token was refreshed
                    if hasattr(response, 'data'):
                        response.data = {'message': 'Token refreshed', 'refreshed': True}
                        response.status_code = 200

                except (InvalidToken, TokenError):
                    # Refresh token is also invalid, clear cookies
                    response.delete_cookie('access_token')
                    response.delete_cookie('refresh_token')

        return response
