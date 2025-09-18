from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models, transaction
from django.core.validators import MaxValueValidator
import uuid
import os
from django.utils.timezone import now, timedelta
from django.conf import settings
from django.utils import timezone
from django.core.files.storage import default_storage

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")

        email = self.normalize_email(email)
        extra_fields.setdefault("username", email.split("@")[0])
        extra_fields.setdefault("is_active", True) 

        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)  

        return self.create_user(email, password, **extra_fields)

def user_profile_path(instance, filename):
    """Generate path for profile pictures"""
    ext = filename.split('.')[-1]
    # Use user_id as fallback if kea_id not available yet
    identifier = getattr(instance, 'kea_id', None) or str(instance.user_id)
    filename = f"profile_{identifier}.{ext}"
    return f"profile_pictures/{identifier}/{filename}"

def membership_card_path(instance, filename):
    """Generate path for membership cards"""
    ext = filename.split('.')[-1]
    identifier = getattr(instance, 'kea_id', None) or str(instance.user_id)
    filename = f"membership_card_{identifier}.{ext}"
    return f"membership_cards/{identifier}/{filename}"

def qr_code_path(instance, filename):
    """Generate path for QR codes"""
    identifier = getattr(instance, 'kea_id', None) or str(instance.user_id)
    return f"qrcodes/{identifier}.png"

class KEASequence(models.Model):
    """Model to track KEA ID sequence"""
    last_number = models.IntegerField(default=100)
    
    class Meta:
        db_table = 'kea_sequence'

class CustomUser(AbstractUser):
    """Custom User model with additional fields and image storage."""
    
    USER_TYPES = (
        ('admin', 'Admin'),
        ('member', 'Member'),
    )
    
    BLOOD_GROUP_CHOICES = (
        ('A+', 'A Positive'),
        ('A-', 'A Negative'),
        ('B+', 'B Positive'),
        ('B-', 'B Negative'),
        ('AB+', 'AB Positive'),
        ('AB-', 'AB Negative'),
        ('O+', 'O Positive'),
        ('O-', 'O Negative'),
    )
    
    # Primary fields
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_type = models.CharField(max_length=20, choices=USER_TYPES)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    
    # Profile fields
    company_name = models.CharField(max_length=50, blank=True, null=True)
    college_name = models.CharField(max_length=50, blank=True, null=True)
    designation = models.CharField(max_length=50, blank=True, null=True)
    department_of_study = models.CharField(max_length=30, blank=True, null=True)
    year_of_graduation = models.IntegerField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    blood_group = models.CharField(
        max_length=3, 
        choices=BLOOD_GROUP_CHOICES, 
        blank=True, 
        null=True,
        help_text="Select your blood group"
    )
    
    # Account status
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    membership_expiry = models.DateTimeField(blank=True, null=True)
    
    # OTP fields
    otp = models.IntegerField(validators=[MaxValueValidator(9999)], null=True, blank=True)
    otp_tries = models.IntegerField(null=True, blank=True, default=0)
    otp_expiry = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    
    # File fields - stored in Railway volume
    profile_picture = models.ImageField(
        upload_to=user_profile_path, 
        blank=True, 
        null=True,
        help_text="Upload profile picture (max 5MB)"
    )
    membership_card = models.FileField(
        upload_to=membership_card_path, 
        blank=True, 
        null=True,
        help_text="Upload membership card PDF or image"
    )
    membership_card_url = models.URLField(null=True, blank=True)
    qr_code = models.ImageField(
        upload_to=qr_code_path, 
        blank=True, 
        null=True,
        help_text="Generated QR code for membership"
    )
    
    # KEA ID
    kea_id = models.CharField(max_length=10, blank=True, null=True, unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'phone_number', 'user_type']
    
    objects = CustomUserManager()
    
    class Meta:
        db_table = 'userdata_customuser'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.email} ({self.kea_id})"
    
    def activate_membership(self):
        """Activate membership for one year"""
        self.membership_expiry = now() + timedelta(days=365)
        self.is_active = True
        self.save()
    
    def membership_is_valid(self):
        """Check and update membership validity"""
        if self.membership_expiry and self.membership_expiry <= now():
            self.is_active = False
            self.save()
        return self.is_active
    
    def get_blood_group_display_with_icon(self):
        """Returns blood group with a blood drop icon"""
        if self.blood_group:
            return f"🩸 {self.get_blood_group_display()}"
        return "Not specified"
    
    def get_profile_picture_url(self):
        """Get profile picture URL or default"""
        if self.profile_picture:
            return self.profile_picture.url
        return '/static/images/default-profile.png'
    
    def save(self, *args, **kwargs):
        # Generate KEA ID if not set
        if not self.kea_id:
            with transaction.atomic():
                seq, created = KEASequence.objects.select_for_update().get_or_create(
                    defaults={'last_number': 100}
                )
                seq.last_number += 1
                seq.save()
                self.kea_id = f"KEA{seq.last_number}"
        
        super().save(*args, **kwargs)
    
    def delete(self, *args, **kwargs):
        """Delete user and associated files safely"""
        # Delete associated files when user is deleted
        files_to_delete = [
            self.profile_picture,
            self.membership_card,
            self.qr_code
        ]
        
        for file_field in files_to_delete:
            if file_field:
                try:
                    # Use default_storage for cloud compatibility
                    if default_storage.exists(file_field.name):
                        default_storage.delete(file_field.name)
                except Exception as e:
                    # Log the error but don't prevent user deletion
                    print(f"Error deleting file {file_field.name}: {e}")
        
        super().delete(*args, **kwargs)

# Remove the duplicate KEASequence class

# Your other models remain the same...
class Payment(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=200.0)  
    order_id = models.CharField(max_length=100, blank=True, null=True)
    payment_id = models.CharField(max_length=100, blank=True, null=True)
    signature = models.CharField(max_length=256, blank=True, null=True)
    status = models.CharField(max_length=20, default='created') 
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class OTPVerification(models.Model):
    phone_number = models.CharField(max_length=15, unique=True)
    otp = models.CharField(max_length=10) 
    otp_expiry = models.DateTimeField()
    verified = models.BooleanField(default=False)
    otp_tries = models.IntegerField(default=0)
    
    def __str__(self):
        return f"{self.phone_number} - {'Verified' if self.verified else 'Not Verified'}"

class PasswordResetToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Reset token for {self.user.email}"
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)
    
    @property
    def is_valid(self):
        return not self.is_used and self.expires_at > timezone.now()
    
    @classmethod
    def create_token(cls, user):
        # Invalidate existing tokens
        cls.objects.filter(user=user, is_used=False).update(is_used=True)
        
        # Create new token
        return cls.objects.create(user=user)
    
    @classmethod
    def validate_token(cls, token_string):
        try:
            token_obj = cls.objects.get(token=token_string, is_used=False)
            if token_obj.is_valid:
                return token_obj
            return None
        except (cls.DoesNotExist, ValueError):
            return None