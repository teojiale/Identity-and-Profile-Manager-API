from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.test import Client
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer

class RegistrationValidationTest(APITestCase):

    def test_valid_username_format(self):
        """Test that valid usernames pass validation"""
        serializer = RegisterSerializer(data={
            'username': 'testuser123',
            'password': 'ValidPass123!'
        })
        self.assertTrue(serializer.is_valid())

    def test_invalid_username_characters(self):
        """Test that usernames with invalid characters are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'test@user',
            'password': 'ValidPass123!'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)
        self.assertEqual(serializer.errors['username'][0],
                        "Username can only contain letters, numbers, and underscores.")

    def test_username_too_short(self):
        """Test that usernames shorter than 3 characters are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'ab',
            'password': 'ValidPass123!'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)

    def test_username_too_long(self):
        """Test that usernames longer than 30 characters are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'a' * 31,
            'password': 'ValidPass123!'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)

    def test_duplicate_username(self):
        """Test that duplicate usernames are rejected"""
        # Create a user first
        User.objects.create_user(username='existinguser', password='pass123')

        serializer = RegisterSerializer(data={
            'username': 'existinguser',
            'password': 'ValidPass123!'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('username', serializer.errors)
        self.assertEqual(serializer.errors['username'][0], "This username is already taken.")

    def test_password_too_short(self):
        """Test that passwords shorter than 8 characters are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'testuser',
            'password': 'short'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertEqual(serializer.errors['password'][0], "Password must be at least 8 characters long.")

    def test_password_missing_uppercase(self):
        """Test that passwords without uppercase letters are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'testuser',
            'password': 'validpass123'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertEqual(serializer.errors['password'][0], "Password must contain at least one uppercase letter.")

    def test_password_missing_lowercase(self):
        """Test that passwords without lowercase letters are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'testuser',
            'password': 'VALIDPASS123'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertEqual(serializer.errors['password'][0], "Password must contain at least one lowercase letter.")

    def test_password_missing_number(self):
        """Test that passwords without numbers are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'testuser',
            'password': 'ValidPassword'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertEqual(serializer.errors['password'][0], "Password must contain at least one number.")

    def test_password_contains_username(self):
        """Test that passwords containing the username are rejected"""
        serializer = RegisterSerializer(data={
            'username': 'testuser',
            'password': 'testuser123'
        })
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)
        self.assertEqual(serializer.errors['password'][0], "Password cannot contain your username.")

    def test_weak_password_rejection(self):
        """Test that common weak passwords are rejected"""
        weak_passwords = ['password', '12345678', 'qwerty', 'abc123']

        for weak_pass in weak_passwords:
            with self.subTest(password=weak_pass):
                serializer = RegisterSerializer(data={
                    'username': 'testuser',
                    'password': weak_pass
                })
                self.assertFalse(serializer.is_valid())
                self.assertIn('password', serializer.errors)
                self.assertEqual(serializer.errors['password'][0],
                                "This password is too common. Please choose a stronger password.")

    def test_valid_registration(self):
        """Test that valid registration data passes all validation"""
        serializer = RegisterSerializer(data={
            'username': 'validuser123',
            'password': 'StrongPass123!'
        })
        self.assertTrue(serializer.is_valid())

        # Test that user creation works
        user = serializer.save()
        self.assertEqual(user.username, 'validuser123')
        self.assertTrue(user.check_password('StrongPass123!'))


class LogoutTest(TestCase):
    """Test cases for logout functionality including JWT token blacklisting"""

    def setUp(self):
        """Set up test user and client"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        self.logout_url = reverse('logout')

    def test_logout_without_refresh_token(self):
        """Test logout without providing refresh token"""
        # Log in the user first
        self.client.login(username='testuser', password='testpass123')

        # Make POST request without refresh token
        response = self.client.post(self.logout_url, {})

        # Should still redirect to home and log out the user
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

        # Check that user is logged out (session should be cleared)
        response = self.client.get(reverse('home'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_logout_with_valid_refresh_token(self):
        """Test logout with valid refresh token"""
        # Create refresh token for the user
        refresh = RefreshToken.for_user(self.user)
        refresh_token = str(refresh)

        # Log in the user first
        self.client.login(username='testuser', password='testpass123')

        # Make POST request with refresh token
        response = self.client.post(self.logout_url, {'refresh': refresh_token})

        # Should redirect to home
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

        # Check that user is logged out (session should be cleared)
        response = self.client.get(reverse('home'))
        self.assertNotIn('_auth_user_id', self.client.session)

        # Verify that the refresh token is blacklisted
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
        blacklisted = BlacklistedToken.objects.filter(token__jti=refresh['jti'])
        self.assertTrue(blacklisted.exists())

    def test_logout_with_invalid_refresh_token(self):
        """Test logout with invalid refresh token"""
        # Log in the user first
        self.client.login(username='testuser', password='testpass123')

        # Make POST request with invalid refresh token
        response = self.client.post(self.logout_url, {'refresh': 'invalid_token'})

        # Should still redirect to home (graceful error handling)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

        # Check that user is still logged out (session should be cleared)
        response = self.client.get(reverse('home'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_logout_with_malformed_refresh_token(self):
        """Test logout with malformed refresh token"""
        # Log in the user first
        self.client.login(username='testuser', password='testpass123')

        # Make POST request with malformed token
        response = self.client.post(self.logout_url, {'refresh': 'not.a.jwt.token'})

        # Should still redirect to home (graceful error handling)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

        # Check that user is logged out
        response = self.client.get(reverse('home'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_logout_without_authentication(self):
        """Test logout when user is not authenticated"""
        # Don't log in the user

        # Make POST request
        response = self.client.post(self.logout_url, {})

        # Should still redirect to home
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

    def test_logout_get_request(self):
        """Test that GET requests to logout are handled gracefully"""
        # Log in the user first
        self.client.login(username='testuser', password='testpass123')

        # Make GET request to logout URL
        response = self.client.get(self.logout_url)

        # Should redirect to home
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('home'))

        # Check that user is logged out
        response = self.client.get(reverse('home'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_logout_clears_session_data(self):
        """Test that logout properly clears all session data"""
        # Log in the user first
        self.client.login(username='testuser', password='testpass123')

        # Add some session data
        session = self.client.session
        session['test_key'] = 'test_value'
        session.save()

        # Verify session data exists
        self.assertEqual(self.client.session['test_key'], 'test_value')

        # Make POST request to logout
        response = self.client.post(self.logout_url, {})

        # Should redirect to home
        self.assertEqual(response.status_code, 302)

        # Check that all session data is cleared
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertNotIn('test_key', self.client.session)

    def test_token_blacklisting_prevents_reuse(self):
        """Test that blacklisted tokens cannot be used for refresh"""
        from rest_framework_simplejwt.views import TokenRefreshView
        from django.test import RequestFactory

        # Create refresh token for the user
        refresh = RefreshToken.for_user(self.user)
        refresh_token = str(refresh)

        # Log in and logout to blacklist the token
        self.client.login(username='testuser', password='testpass123')
        self.client.post(self.logout_url, {'refresh': refresh_token})

        # Verify token is blacklisted
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
        blacklisted = BlacklistedToken.objects.filter(token__jti=refresh['jti'])
        self.assertTrue(blacklisted.exists())

        # Try to use the blacklisted token for refresh
        factory = RequestFactory()
        request = factory.post('/token/refresh/', {'refresh': refresh_token})

        view = TokenRefreshView.as_view()
        response = view(request)

        # Should fail with 401 Unauthorized
        self.assertEqual(response.status_code, 401)
