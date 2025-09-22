from django.shortcuts import render
from rest_framework import viewsets, permissions, serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.decorators import action
from rest_framework.parsers import JSONParser
from .models import IdentityProfile, Consent
from .serializers import IdentityProfileSerializer, RegisterSerializer
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.utils.decorators import method_decorator
from django.http import JsonResponse, HttpResponse
from django.middleware.csrf import get_token
from django.conf import settings
from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenObtainPairView
import re

# Custom validators
def validate_name(value):
    """Validate name fields - should contain only letters, spaces, hyphens, and apostrophes"""
    if value and not re.match(r"^[a-zA-Z\s\-']+$", value):
        raise ValidationError(
            "Name can only contain letters, spaces, hyphens, and apostrophes.",
            code='invalid_name'
        )

def validate_phone_number(value):
    """Validate phone number format"""
    if value:
        # Remove all non-digit characters for validation
        digits_only = re.sub(r'\D', '', value)
        if len(digits_only) < 10 or len(digits_only) > 15:
            raise ValidationError(
                "Phone number must be between 10-15 digits.",
                code='invalid_phone_length'
            )
        # Check for valid phone number pattern (flexible international format)
        if not re.match(r'^[\+]?[1-9][\d]{9,14}$', digits_only):
            raise ValidationError(
                "Please enter a valid phone number.",
                code='invalid_phone_format'
            )

def validate_pronoun(value):
    """Validate pronoun format - should be simple pronoun combinations"""
    if value:
        # Allow common pronoun patterns like "he/him", "she/her", "they/them", etc.
        if not re.match(r'^[a-zA-Z/]{1,20}$', value):
            raise ValidationError(
                "Pronouns should be in format like 'he/him' or 'they/them'.",
                code='invalid_pronoun'
            )

def validate_address(value):
    """Validate address - should not be just whitespace and have reasonable length"""
    if value:
        if len(value.strip()) < 10:
            raise ValidationError(
                "Please provide a complete address.",
                code='address_too_short'
            )
        if len(value) > 500:
            raise ValidationError(
                "Address is too long (maximum 500 characters).",
                code='address_too_long'
            )

# Form for profile editing
class ProfileEditForm(forms.ModelForm):
    class Meta:
        model = IdentityProfile
        fields = [
            'email', 'occupation', 'age', 'gender_identity', 'pronoun',
            'legal_name', 'birth_name', 'native_name', 'home_address',
            'emergency_contact', 'phone_number'
        ]
        widgets = {
            'email': forms.EmailInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'your.email@example.com (optional)'
            }),
            'occupation': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'e.g., Software Developer, Teacher, Student (optional)'
            }),
            'age': forms.NumberInput(attrs={
                'class': 'form-number-input-custom',
                'min': '1',
                'max': '150',
                'placeholder': 'Enter your age (optional)'
            }),
            'gender_identity': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'e.g., Male, Female, Non-binary, etc. (optional)'
            }),
            'pronoun': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'e.g., he/him, she/her, they/them (optional)'
            }),
            'legal_name': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'Your full legal name (optional)'
            }),
            'birth_name': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'Name given at birth (if different) (optional)'
            }),
            'native_name': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'Name in your native language/culture (optional)'
            }),
            'home_address': forms.Textarea(attrs={
                'class': 'form-textarea-custom',
                'rows': 3,
                'placeholder': 'Your complete home address (optional)'
            }),
            'emergency_contact': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': 'Emergency contact name and relationship (optional)'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-input-custom',
                'placeholder': '+1 (555) 123-4567 or local format (optional)'
            }),
        }

    # Add visibility fields
    email_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Email Visibility",
        required=False
    )
    occupation_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Occupation Visibility",
        required=False
    )
    age_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Age Visibility",
        required=False
    )
    gender_identity_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Gender Identity Visibility",
        required=False
    )
    pronoun_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Pronoun Visibility",
        required=False
    )
    legal_name_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Legal Name Visibility",
        required=False
    )
    birth_name_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Birth Name Visibility",
        required=False
    )
    native_name_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Native Name Visibility",
        required=False
    )
    home_address_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Home Address Visibility",
        required=False
    )
    emergency_contact_visibility = forms.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        widget=forms.Select(attrs={'class': 'form-select-custom visibility-select'}),
        label="Emergency Contact Visibility",
        required=False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            # Set initial values for visibility fields
            for field_name in ['email', 'occupation', 'age', 'gender_identity', 'pronoun',
                             'legal_name', 'birth_name', 'native_name', 'home_address', 'emergency_contact']:
                visibility_field = f"{field_name}_visibility"
                self.fields[visibility_field].initial = getattr(self.instance, visibility_field)

        # Add validation classes and data attributes for client-side validation
        for field_name, field in self.fields.items():
            if hasattr(field.widget, 'attrs'):
                current_class = field.widget.attrs.get('class', '')
                field.widget.attrs.update({
                    'data-field': field_name,
                    'data-validate': 'true'
                })

    # Custom field validation methods
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            # Additional email validation beyond Django's built-in validator
            if len(email) > 254:
                raise ValidationError(
                    "Email address is too long (maximum 254 characters).",
                    code='email_too_long'
                )

            # Check for common typos or suspicious patterns
            if re.search(r'[<>]', email):
                raise ValidationError(
                    "Email address contains invalid characters.",
                    code='email_invalid_chars'
                )
        return email

    def clean_age(self):
        age = self.cleaned_data.get('age')
        if age is not None and age < 13:
            raise ValidationError(
                "You must be at least 13 years old to use this service.",
                code='age_too_young'
            )
        if age is not None and age > 150:
            raise ValidationError(
                "Age cannot exceed 150 years.",
                code='age_too_old'
            )
        return age

    def clean_occupation(self):
        occupation = self.cleaned_data.get('occupation')
        if occupation and len(occupation) > 100:
            raise ValidationError(
                "Occupation description is too long (maximum 100 characters).",
                code='occupation_too_long'
            )
        return occupation

    def clean_gender_identity(self):
        gender_identity = self.cleaned_data.get('gender_identity')
        if gender_identity and len(gender_identity) > 100:
            raise ValidationError(
                "Gender identity description is too long (maximum 100 characters).",
                code='gender_identity_too_long'
            )
        return gender_identity

    def clean_pronoun(self):
        pronoun = self.cleaned_data.get('pronoun')
        if pronoun:
            validate_pronoun(pronoun)
        return pronoun

    def clean_legal_name(self):
        legal_name = self.cleaned_data.get('legal_name')
        if legal_name:
            validate_name(legal_name)
            if len(legal_name) > 100:
                raise ValidationError(
                    "Legal name is too long (maximum 100 characters).",
                    code='legal_name_too_long'
                )
        return legal_name

    def clean_birth_name(self):
        birth_name = self.cleaned_data.get('birth_name')
        if birth_name:
            validate_name(birth_name)
            if len(birth_name) > 100:
                raise ValidationError(
                    "Birth name is too long (maximum 100 characters).",
                    code='birth_name_too_long'
                )
        return birth_name

    def clean_native_name(self):
        native_name = self.cleaned_data.get('native_name')
        if native_name:
            validate_name(native_name)
            if len(native_name) > 100:
                raise ValidationError(
                    "Native name is too long (maximum 100 characters).",
                    code='native_name_too_long'
                )
        return native_name

    def clean_home_address(self):
        home_address = self.cleaned_data.get('home_address')
        if home_address:
            validate_address(home_address)
        return home_address

    def clean_emergency_contact(self):
        emergency_contact = self.cleaned_data.get('emergency_contact')
        if emergency_contact and len(emergency_contact) > 200:
            raise ValidationError(
                "Emergency contact information is too long (maximum 200 characters).",
                code='emergency_contact_too_long'
            )
        return emergency_contact

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if phone_number:
            validate_phone_number(phone_number)
        return phone_number

    def clean(self):
        cleaned_data = super().clean()
        # Cross-field validation can be added here if needed
        return cleaned_data

# Create your views here.


# Display requested data
class IdentityProfileViewSet(viewsets.ViewSet):
        permission_classes = [permissions.IsAuthenticated]
        lookup_field = "username"  # use username in URL instead of pk

        def get_object(self):
                username = self.kwargs.get(self.lookup_field)
                target_user = get_object_or_404(User, username=username)
                profile = get_object_or_404(IdentityProfile, user=target_user)
                return profile, target_user
        
        def retrieve(self, request, username=None):
                profile, target_user = self.get_object()

                # Allow full access only to owner
                if request.user == target_user:
                        serializer = IdentityProfileSerializer(profile)
                        return Response(serializer.data)

                # Otherwise, show limited fields with consent
                field_names = ["academic_name", "social_name", "legal_name"]
                visible_fields = {}

                for field in field_names:
                        if Consent.objects.filter(
                                owner=target_user, requester=request.user, field_name=field
                        ).exists():
                                visible_fields[field] = getattr(profile, field)

                visible_fields["username"] = target_user.username
                return Response(visible_fields)

        @action(detail=False, methods=["get"], url_path="search")
        def search(self, request):
                query = request.query_params.get("q", "").strip()
                if not query:
                        return Response(
                                {"error": "Please provide a search query."},
                                status=status.HTTP_400_BAD_REQUEST,
                        )

                # Partial match on username
                users = User.objects.filter(username__icontains=query)

                if not users.exists():
                        return Response({"error": "No matches found."}, status=status.HTTP_200_OK)

                results = []
                for user in users:
                        profile = IdentityProfile.objects.filter(user=user).first()
                        if not profile:
                                continue

                        limited_fields = {"username": user.username}

                        # Optionally, add fields with consent or leave minimal info
                        field_names = ["legal_name", "birth_name", "native_name"]
                        for field in field_names:
                                # Only check consent if user is authenticated
                                if request.user.is_authenticated and Consent.objects.filter(
                                        owner=user, requester=request.user, field_name=field
                                ).exists():
                                        limited_fields[field] = getattr(profile, field)

                        results.append(limited_fields)

                return Response(results, status=status.HTTP_200_OK)

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return render(request, "registrationform.html")

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)  # uses JSON body
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User created successfully"}, status=201)
        return Response(serializer.errors, status=400)


def check_username(request):
    if request.method != "GET":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    username = request.GET.get("username", "").strip()
    if not username:
        return JsonResponse({"available": False, "error": "username is required"}, status=400)

    exists = User.objects.filter(username=username).exists()
    return JsonResponse({"available": not exists})
        
# Display home page
def home (request):
       return render(request, "home.html")

# Login page
def login_page(request):
       return render(request, "login.html")

# Display Profile Details
def profile_detail(request, username):
    user = get_object_or_404(User, username=username)
    profile = get_object_or_404(IdentityProfile, user=user)

    # Get visible fields based on requesting user's permissions
    visible_fields = {}
    requesting_user = request.user

    # Define all profile fields
    profile_fields = [
        'email', 'occupation', 'age', 'gender_identity', 'pronoun',
        'legal_name', 'birth_name', 'native_name', 'home_address',
        'emergency_contact', 'phone_number'
    ]

    for field_name in profile_fields:
        if profile.can_view_field(field_name, requesting_user):
            visible_fields[field_name] = getattr(profile, field_name)

    context = {
        "username": user.username,
        "profile": profile,
        "visible_fields": visible_fields,
        "is_owner": requesting_user == user,
        "is_admin": requesting_user.is_staff or requesting_user.is_superuser,
    }

    return render(request, "profile_detail.html", context)

# Profile Edit View
@login_required
def profile_edit(request):
    profile = get_object_or_404(IdentityProfile, user=request.user)

    if request.method == 'POST':
        form = ProfileEditForm(request.POST, instance=profile)
        if form.is_valid():
            # Save the profile data
            profile = form.save(commit=False)

            # Save visibility settings
            for field_name in ['email', 'occupation', 'age', 'gender_identity', 'pronoun',
                             'legal_name', 'birth_name', 'native_name', 'home_address', 'emergency_contact']:
                visibility_field = f"{field_name}_visibility"
                visibility_value = form.cleaned_data.get(visibility_field)
                if visibility_value:  # Only set if the field was provided
                    setattr(profile, visibility_field, visibility_value)

            profile.save()

            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('profile_detail', username=request.user.username)
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = ProfileEditForm(instance=profile)

    context = {
        'form': form,
        'profile': profile,
    }

    return render(request, 'profile_edit.html', context)

# Custom JWT Cookie Views for secure token handling
class CookieTokenObtainPairView(APIView):
    """
    Custom token obtain view that sets httpOnly cookies instead of returning tokens in JSON
    """
    permission_classes = [AllowAny]

    def post(self, request):
        # Use the standard TokenObtainPairView logic but intercept the response
        from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

        serializer = TokenObtainPairSerializer(data=request.data)
        if serializer.is_valid():
            # Get the tokens
            refresh_token = serializer.validated_data['refresh']
            access_token = serializer.validated_data['access']

            # Create response
            response = JsonResponse({
                'message': 'Login successful',
                'user': {
                    'id': serializer.user.id,
                    'username': serializer.user.username
                }
            }, status=200)

            # Set httpOnly cookies for both tokens
            # In production, set secure=True when using HTTPS
            is_production = not settings.DEBUG

            response.set_cookie(
                key='access_token',
                value=str(access_token),
                httponly=True,
                secure=is_production,  # Secure in production (HTTPS required)
                samesite='Strict',
                max_age=300  # 5 minutes (matches ACCESS_TOKEN_LIFETIME)
            )

            response.set_cookie(
                key='refresh_token',
                value=str(refresh_token),
                httponly=True,
                secure=is_production,  # Secure in production (HTTPS required)
                samesite='Strict',
                max_age=86400  # 1 day (matches REFRESH_TOKEN_LIFETIME)
            )

            # Also log the user in with Django session for template-based views
            login(request, serializer.user)

            return response
        else:
            return JsonResponse(serializer.errors, status=400)


class CookieTokenRefreshView(APIView):
    """
    Custom token refresh view that reads refresh token from cookie and sets new access token cookie
    """
    permission_classes = [AllowAny]

    def post(self, request):
        # Get refresh token from cookie
        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return JsonResponse({'detail': 'No refresh token provided'}, status=401)

        try:
            # Validate and refresh the token
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            # Create response
            response = JsonResponse({
                'message': 'Token refreshed successfully'
            }, status=200)

            # Set new access token cookie
            from django.conf import settings
            is_production = not settings.DEBUG

            response.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=is_production,  # Secure in production (HTTPS required)
                samesite='Strict',
                max_age=300  # 5 minutes
            )

            # Also set new refresh token if rotation is enabled
            if getattr(settings, 'SIMPLE_JWT', {}).get('ROTATE_REFRESH_TOKENS', False):
                new_refresh_token = str(refresh)
                response.set_cookie(
                    key='refresh_token',
                    value=new_refresh_token,
                    httponly=True,
                    secure=is_production,  # Secure in production (HTTPS required)
                    samesite='Strict',
                    max_age=86400  # 1 day
                )

            return response

        except TokenError as e:
            return JsonResponse({'detail': 'Invalid refresh token'}, status=401)


class CookieLogoutView(APIView):
    """
    Logout view that clears the JWT cookies
    """
    def post(self, request):
        response = JsonResponse({'message': 'Logged out successfully'}, status=200)

        # Clear the cookies
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')

        # Also logout from Django session
        logout(request)

        return response


def get_csrf_token(request):
    """
    View to get CSRF token for frontend
    """
    if request.method == 'GET':
        token = get_token(request)
        return JsonResponse({'csrfToken': token})
    return JsonResponse({'error': 'Method not allowed'}, status=405)




# Logout view (updated for cookie-based authentication)
def logout_view(request):
    # Try to blacklist tokens from cookies if they exist
    try:
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            from rest_framework_simplejwt.tokens import RefreshToken
            token = RefreshToken(refresh_token)
            print(f"Blacklisting token: {token}")
            token.blacklist()
    except Exception as e:
        print(f"Error blacklisting token: {e}")
        pass

    # Logout from Django session
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('home')