from rest_framework import serializers
from .models import CustomUser

from rest_framework import serializers
from django.core.validators import RegexValidator
from .models import CustomUser
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import PasswordResetToken
from django.utils import timezone
import os
User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(
        validators=[RegexValidator(regex=r'^\+?[1-9]\d{9,14}$', message="Enter a valid phone number.")]
    )
    first_name = serializers.CharField(required=True, max_length=30)
    last_name = serializers.CharField(required=True, max_length=30)
    blood_group = serializers.ChoiceField(
        choices=CustomUser.BLOOD_GROUP_CHOICES,
        required=False,
        allow_blank=True,
        help_text="Select your blood group"
    )
    
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name','user_type', 'email', 'phone_number', 'username',
                  'company_name', 'designation', 'department_of_study',
                  'year_of_graduation', 'address', 'blood_group', 
                  'password', 'profile_picture','college_name']
        
        extra_kwargs = {'password': {'write_only': True}}
    
    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email is already registered.")
        return value
    
    def validate_blood_group(self, value):
        """Validate blood group format"""
        if value and value not in [choice[0] for choice in CustomUser.BLOOD_GROUP_CHOICES]:
            raise serializers.ValidationError("Invalid blood group selection.")
        return value
    
    def validate_profile_picture(self, value):
        """Validate uploaded profile picture"""
        if value:
            # Check file size (5MB limit)
            if value.size > 5 * 1024 * 1024:
                raise serializers.ValidationError("Image file too large (5MB max)")
            
            # Check file type
            if not value.content_type.startswith('image/'):
                raise serializers.ValidationError("File must be an image")
            
            # Check file extension
            allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
            ext = os.path.splitext(value.name)[1].lower()
            if ext not in allowed_extensions:
                raise serializers.ValidationError("Unsupported file format. Use JPG, PNG, GIF, or WebP")
        
        return value
    
    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        user.is_active = (user.user_type == "admin")
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):
    profile_picture_url = serializers.SerializerMethodField()
    qr_code_url = serializers.SerializerMethodField()
    membership_card_url = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomUser
        fields = [
            'user_id', 'first_name', 'last_name','username', 'email', 'phone_number', 
            'company_name', 'college_name', 'designation',
            'department_of_study', 'year_of_graduation', 
            'address', 'blood_group', 'kea_id', 'user_type',
            'profile_picture', 'profile_picture_url', 
            'qr_code_url', 'membership_card_url'
        ]
        read_only_fields = ['user_id', 'email', 'phone_number', 'kea_id']
    
    def get_profile_picture_url(self, obj):
        """Return full URL for profile picture"""
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None
    
    def get_qr_code_url(self, obj):
        """Return full URL for QR code"""
        if obj.qr_code:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.qr_code.url)
            return obj.qr_code.url
        return None
    
    def get_membership_card_url(self, obj):
        """Return full URL for membership card"""
        if obj.membership_card:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.membership_card.url)
            return obj.membership_card.url
        return None
    
class UserUpdateSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(
        validators=[RegexValidator(regex=r'^\+?[1-9]\d{9,14}$', message="Enter a valid phone number.")]
    )
    first_name = serializers.CharField(required=False, max_length=30)
    last_name = serializers.CharField(required=False, max_length=30)
    blood_group = serializers.ChoiceField(
        choices=CustomUser.BLOOD_GROUP_CHOICES,
        required=False,
        allow_blank=True,
    )
    
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name','username', 'phone_number', 'company_name', 'designation', 
                  'department_of_study', 'year_of_graduation', 'address', 
                  'blood_group', 'profile_picture','college_name']
    
    def validate_phone_number(self, value):
        if self.instance and self.instance.phone_number != value:
            if CustomUser.objects.filter(phone_number=value).exists():
                raise serializers.ValidationError("Phone number is already registered.")
        return value
    
    def validate_blood_group(self, value):
        if value and value not in [choice[0] for choice in CustomUser.BLOOD_GROUP_CHOICES]:
            raise serializers.ValidationError("Invalid blood group selection.")
        return value
    
    def validate_profile_picture(self, value):
        """Validate uploaded profile picture during updates"""
        if value:
            # Check file size (5MB limit)
            if value.size > 5 * 1024 * 1024:
                raise serializers.ValidationError("Image file too large (5MB max)")
            
            # Check file type
            if not value.content_type.startswith('image/'):
                raise serializers.ValidationError("File must be an image")
            
            # Check file extension
            allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
            ext = os.path.splitext(value.name)[1].lower()
            if ext not in allowed_extensions:
                raise serializers.ValidationError("Unsupported file format. Use JPG, PNG, GIF, or WebP")
        
        return value
    
    def update(self, instance, validated_data):
        """Custom update method to handle old profile picture deletion"""
        # If a new profile picture is being uploaded, delete the old one
        if 'profile_picture' in validated_data and validated_data['profile_picture']:
            old_picture = instance.profile_picture
            if old_picture:
                try:
                    from django.core.files.storage import default_storage
                    if default_storage.exists(old_picture.name):
                        default_storage.delete(old_picture.name)
                except Exception as e:
                    # Log the error but don't prevent the update
                    print(f"Error deleting old profile picture: {e}")
        
        return super().update(instance, validated_data)


class RequestPasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset requests"""
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        """Validate that the email exists in the database"""
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            # For security reasons, don't disclose that the email doesn't exist
            # Just validate normally and we'll handle this in the view
            pass
        return value

class ValidateTokenSerializer(serializers.Serializer):
    """Serializer for validating a reset token"""
    token = serializers.UUIDField(required=True)

class ResetPasswordSerializer(serializers.Serializer):
    """Serializer for resetting a password with a token"""
    token = serializers.UUIDField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    confirm_password = serializers.CharField(required=True, write_only=True)
    
    def validate(self, data):
        """Validate that passwords match and token is valid"""
        # Check that passwords match
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords don't match."})
        
        # Validate password strength
        try:
            validate_password(data['password'])
        except Exception as e:
            raise serializers.ValidationError({"password": list(e.messages)})
        
        # Validate the token
        token_obj = PasswordResetToken.validate_token(data['token'])
        if not token_obj:
            raise serializers.ValidationError({"token": "Invalid or expired token."})
        
        # Add token object to validated data
        data['token_obj'] = token_obj
        return data



class BloodGroupUpdateSerializer(serializers.ModelSerializer):
    blood_group = serializers.ChoiceField(
        choices=CustomUser.BLOOD_GROUP_CHOICES,
        required=True,
        help_text="Select your blood group"
    )
    
    class Meta:
        model = CustomUser
        fields = ['blood_group']
    
    def validate_blood_group(self, value):
        if not value:
            raise serializers.ValidationError("Blood group is required.")
        return value
    profile_picture_url = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomUser
        fields = [
            'user_id', 'username', 'email', 'phone_number',
            'is_active', 'membership_expiry', 'user_type',
            'membership_card_url', 'qr_code', 'profile_picture', 'profile_picture_url'
        ]
    
    def get_profile_picture_url(self, obj):
        """Return the full URL for the profile picture"""
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None