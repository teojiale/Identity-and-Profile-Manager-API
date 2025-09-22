from django.db import models
from django.contrib.auth.models import User
from django.core.validators import EmailValidator, MinValueValidator, MaxValueValidator
from django.conf import settings
from cryptography.fernet import Fernet
import base64
import uuid

# Visibility choices for profile fields
VISIBILITY_CHOICES = [
    ('public', 'Public'),
    ('admin', 'Admin Only'),
    ('private', 'Private'),
]


class EncryptedFieldMixin:
    """Mixin to provide encryption/decryption for model fields"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Use FERNET_KEY from settings, fallback to SECRET_KEY
        key = getattr(settings, 'FERNET_KEY', settings.SECRET_KEY[:32])

        # If key is already base64-encoded (44 chars), use it directly
        if len(key) == 44 and '=' in key:
            key_bytes = key.encode()
        else:
            # Generate a proper base64-encoded key from raw bytes
            if len(key) < 32:
                key = key.ljust(32, '0')[:32]
            key_bytes = base64.urlsafe_b64encode(key.encode())

        self.fernet = Fernet(key_bytes)

    def get_prep_value(self, value):
        """Encrypt value before saving to database"""
        if value is None or value == '':
            return value
        try:
            encrypted = self.fernet.encrypt(str(value).encode())
            return encrypted.decode()
        except Exception:
            # If encryption fails, return the original value (for migration purposes)
            return value

    def from_db_value(self, value, expression, connection):
        """Decrypt value when loading from database"""
        if value is None or value == '':
            return value
        try:
            decrypted = self.fernet.decrypt(value.encode())
            return decrypted.decode()
        except Exception:
            # If decryption fails, return the original value (for migration purposes)
            return value


class EncryptedCharField(EncryptedFieldMixin, models.CharField):
    """Encrypted character field"""
    pass


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    """Encrypted text field"""
    pass

class IdentityProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Basic information
    email = EncryptedCharField(max_length=254, blank=True, validators=[EmailValidator()])
    occupation = models.CharField(max_length=100, blank=True)
    age = models.PositiveIntegerField(blank=True, null=True, validators=[MinValueValidator(1), MaxValueValidator(150)])
    gender_identity = models.CharField(max_length=100, blank=True)
    pronoun = models.CharField(max_length=50, blank=True)

    # Names
    legal_name = models.CharField(max_length=100, blank=True)
    birth_name = models.CharField(max_length=100, blank=True)
    native_name = models.CharField(max_length=100, blank=True)

    # Contact information (encrypted)
    home_address = EncryptedTextField(blank=True)
    emergency_contact = EncryptedCharField(max_length=200, blank=True)
    phone_number = EncryptedCharField(max_length=20, blank=True)

    # Visibility settings for each field
    email_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='private')
    occupation_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='public')
    age_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='private')
    gender_identity_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='private')
    pronoun_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='public')
    legal_name_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='public')
    birth_name_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='private')
    native_name_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='public')
    home_address_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='private')
    emergency_contact_visibility = models.CharField(max_length=10, choices=VISIBILITY_CHOICES, default='private')

    # Profile metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    profile_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"

    def get_field_visibility(self, field_name):
        """Get the visibility setting for a specific field"""
        visibility_field = f"{field_name}_visibility"
        return getattr(self, visibility_field, 'private')

    def can_view_field(self, field_name, requesting_user):
        """Check if a user can view a specific field"""
        if requesting_user == self.user:
            return True  # Owner can always see their own data

        visibility = self.get_field_visibility(field_name)
        if visibility == 'public':
            return True
        elif visibility == 'admin':
            return requesting_user.is_staff or requesting_user.is_superuser
        else:  # private
            return False

class Consent(models.Model):
    """Model for handling specific field access requests and consents"""
    owner = models.ForeignKey(User, related_name="consent_owner", on_delete=models.CASCADE)
    requester = models.ForeignKey(User, related_name="consent_requester", on_delete=models.CASCADE)
    field_name = models.CharField(max_length=50)
    granted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    consent_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    class Meta:
        unique_together = ['owner', 'requester', 'field_name']

    def __str__(self):
        return f"{self.requester.username} can view {self.field_name} of {self.owner.username}"
    