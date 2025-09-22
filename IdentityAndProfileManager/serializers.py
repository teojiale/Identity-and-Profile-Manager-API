from rest_framework import serializers
from .models import IdentityProfile, Consent
from django.contrib.auth.models import User

# Serializer for profile with visibility controls
class IdentityProfileSerializer(serializers.ModelSerializer):
    # Add visibility fields
    email_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    occupation_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    age_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    gender_identity_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    pronoun_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    legal_name_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    birth_name_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    native_name_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    home_address_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )
    emergency_contact_visibility = serializers.ChoiceField(
        choices=[('public', 'Public'), ('admin', 'Admin Only'), ('private', 'Private')],
        required=False
    )

    class Meta:
        model = IdentityProfile
        fields = [
            'user', 'email', 'occupation', 'age', 'gender_identity', 'pronoun',
            'legal_name', 'birth_name', 'native_name', 'home_address',
            'emergency_contact', 'phone_number', 'created_at', 'updated_at',
            'profile_uuid', 'email_visibility', 'occupation_visibility',
            'age_visibility', 'gender_identity_visibility', 'pronoun_visibility',
            'legal_name_visibility', 'birth_name_visibility', 'native_name_visibility',
            'home_address_visibility', 'emergency_contact_visibility'
        ]

# Serializer for profile data with visibility filtering
class ProfileViewSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = IdentityProfile
        fields = [
            'username', 'email', 'occupation', 'age', 'gender_identity', 'pronoun',
            'legal_name', 'birth_name', 'native_name', 'home_address',
            'emergency_contact', 'phone_number'
        ]

    def to_representation(self, instance):
        """
        Filter fields based on requesting user's permissions
        """
        data = super().to_representation(instance)
        request = self.context.get('request')

        if request and request.user:
            requesting_user = request.user
            # Filter out fields that user cannot view
            profile_fields = [
                'email', 'occupation', 'age', 'gender_identity', 'pronoun',
                'legal_name', 'birth_name', 'native_name', 'home_address', 'emergency_contact'
            ]

            for field_name in profile_fields:
                if not instance.can_view_field(field_name, requesting_user):
                    data[field_name] = None

        return data

# Consent serializer
class ConsentSerializer(serializers.ModelSerializer):
    owner_username = serializers.CharField(source='owner.username', read_only=True)
    requester_username = serializers.CharField(source='requester.username', read_only=True)

    class Meta:
        model = Consent
        fields = [
            'consent_uuid', 'owner', 'owner_username', 'requester',
            'requester_username', 'field_name', 'granted_at', 'expires_at'
        ]
        read_only_fields = ['consent_uuid', 'granted_at']

# register new users (simplified: username, password)
class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=30)
    password = serializers.CharField(write_only=True)

    def validate_username(self, value: str) -> str:
        # Check length
        if len(value) < 3:
            raise serializers.ValidationError(
                "Username must be at least 3 characters long."
            )

        if len(value) > 30:
            raise serializers.ValidationError(
                "Username cannot be longer than 30 characters."
            )

        # Check format: only letters, numbers, and underscores
        import re
        if not re.match(r'^[A-Za-z0-9_]+$', value):
            raise serializers.ValidationError(
                "Username can only contain letters, numbers, and underscores."
            )

        # Check for existing username
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")

        return value

    def validate_password(self, value: str) -> str:
        import re

        # Check for common weak passwords first (regardless of other requirements)
        weak_passwords = [
            'password', '12345678', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', '123456789', 'iloveyou'
        ]
        if value.lower() in weak_passwords:
            raise serializers.ValidationError(
                "This password is too common. Please choose a stronger password."
            )

        # Check minimum length
        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )

        # Check if password contains username
        if hasattr(self, 'initial_data') and 'username' in self.initial_data:
            username = self.initial_data['username'].lower()
            if username in value.lower():
                raise serializers.ValidationError(
                    "Password cannot contain your username."
                )

        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )

        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )

        # Check for at least one digit
        if not re.search(r'\d', value):
            raise serializers.ValidationError(
                "Password must contain at least one number."
            )

        return value

    def create(self, validated_data):
        # create the user
        user = User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"],
        )

        # create identity profile with empty optional fields
        IdentityProfile.objects.create(user=user)

        return user