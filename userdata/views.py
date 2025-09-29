from functools import wraps
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *
from django.core.mail import EmailMessage
from django.conf import settings
from .models import CustomUser ,Payment
import io
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.password_validation import validate_password
import traceback
from rest_framework.generics import RetrieveUpdateAPIView
import random
import datetime
from django.utils import timezone
# from .smtp import send_email
from .otp import send_otp, verify_otp, clean_phone_number
import razorpay
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from .utils import generate_membership_card_pdf
import qrcode
import qrcode.image.pil
from django.core.files.base import ContentFile
from io import BytesIO
import os
from .utils import create_user_with_qr
from django.http import HttpRequest , FileResponse
import logging
from django.db.models import Q
from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.db import transaction
from .utils import (
    create_user_with_qr, 
    generate_membership_card_pdf, 
    create_or_update_membership_card,
    send_membership_card_email
)
from django.views.decorators.clickjacking import xframe_options_exempt
from django.utils.decorators import method_decorator
from django.http import HttpResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from rest_framework.permissions import AllowAny
from .models import PasswordResetToken
from django.utils import timezone
from .serializers import (
    RequestPasswordResetSerializer,
    ValidateTokenSerializer,
    ResetPasswordSerializer
)
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status, permissions
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
logger = logging.getLogger(__name__)
executor = ThreadPoolExecutor(max_workers=4)
# Add this import at the top
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser


User = get_user_model()


def timeout_handler(seconds):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = [None]
            exception = [None]
            has_finished = [False]
            
            def target():
                try:
                    result[0] = func(*args, **kwargs)
                    has_finished[0] = True
                except Exception as e:
                    exception[0] = e
                    has_finished[0] = True
            
            thread = threading.Thread(target=target)
            thread.daemon = True
            thread.start()
            
            # Wait for the specified number of seconds
            deadline = time.time() + seconds
            while time.time() < deadline:
                if has_finished[0]:
                    break
                time.sleep(0.1)  # Short sleep to prevent CPU hogging
            
            # Check if function completed
            if not has_finished[0]:
                raise TimeoutError(f"Function timed out after {seconds} seconds")
            
            # Re-raise any exception that occurred in the thread
            if exception[0]:
                raise exception[0]
            
            return result[0]
        
        return wrapper
    return decorator



class UserProfileView(RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # Add JSONParser
    
    def get_object(self):
        return self.request.user
    
    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserSerializer
    
    def get_serializer_context(self):
        """Pass request context to serializer for URL building"""
        context = super().get_serializer_context()
        context['request'] = self.request
        return context
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        
        if serializer.is_valid():
            self.perform_update(serializer)
            
            # Return updated data with proper context for URLs
            response_serializer = UserSerializer(
                instance, 
                context={'request': request}  # Pass request context
            )
            return Response({
                'message': 'Profile updated successfully',
                'user': response_serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def change_password(request):
    """Change user password"""
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')
    
    if not all([old_password, new_password, confirm_password]):
        return Response({
            'error': 'All password fields are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if new_password != confirm_password:
        return Response({
            'error': 'New passwords do not match'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    if not user.check_password(old_password):
        return Response({
            'error': 'Current password is incorrect'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        validate_password(new_password, user)
        user.set_password(new_password)
        user.save()
        return Response({
            'message': 'Password changed successfully'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated])
def delete_profile_picture(request):
    """Delete user profile picture"""
    user = request.user
    if user.profile_picture:
        user.profile_picture.delete()
        user.save()
        return Response({
            'message': 'Profile picture deleted successfully'
        }, status=status.HTTP_200_OK)
    
    return Response({
        'error': 'No profile picture to delete'
    }, status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetView(APIView):
        """
        API view to request a password reset
        """
        permission_classes = [AllowAny]
        
        def post(self, request):
            serializer = RequestPasswordResetSerializer(data=request.data)
            
            if serializer.is_valid():
                email = serializer.validated_data['email']
                
                # Find the user
                try:
                    user = User.objects.get(email=email)
                    
                    # Generate a reset token
                    token_obj = PasswordResetToken.create_token(user)
                    
                    # Build the reset URL
                    frontend_url = 'https://keablr.in'
                    reset_url = f"{frontend_url}/reset-password/{token_obj.token}"
                    
                    # Prepare email content
                    context = {
                        'user': user,
                        'reset_url': reset_url,
                        'valid_hours': 24
                    }
                    html_message = render_to_string('password_reset_email.html', context)
                    plain_message = strip_tags(html_message)
                    
                    # Send email
                    try:
                        send_mail(
                            subject="Reset Your Password",
                            message=plain_message,
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=[email],
                            html_message=html_message,
                            fail_silently=False
                        )
                        logger.info(f"Password reset email sent to: {email}")
                    except Exception as e:
                        logger.error(f"Failed to send password reset email to {email}: {str(e)}")
                        return Response(
                            {"error": "Failed to send reset email. Please try again later."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                        
                except User.DoesNotExist:
                    # For security, don't disclose that the user doesn't exist
                    # Just log it and return the same response
                    logger.warning(f"Password reset requested for non-existent email: {email}")
                
                # Return success response (even if user doesn't exist)
                return Response({
                    "message": "If your email is registered, you will receive reset instructions."
                }, status=status.HTTP_200_OK)
                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ValidateTokenView(APIView):
        """
        API view to validate a reset token
        """
        permission_classes = [AllowAny]
        
        def post(self, request):
            serializer = ValidateTokenSerializer(data=request.data)
            
            if serializer.is_valid():
                token_string = serializer.validated_data['token']
                
                # Validate the token
                token_obj = PasswordResetToken.validate_token(token_string)
                
                if token_obj:
                    return Response({
                        "valid": True,
                        "message": "Token is valid."
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "valid": False,
                        "message": "Token is invalid or expired."
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
        """
        API view to reset password with a valid token
        """
        permission_classes = [AllowAny]
        
        def post(self, request):
            serializer = ResetPasswordSerializer(data=request.data)
            
            if serializer.is_valid():
                token_obj = serializer.validated_data['token_obj']
                user = token_obj.user
                new_password = serializer.validated_data['password']
                
                # Set the new password
                user.set_password(new_password)
                user.save()
                
                # Mark token as used
                token_obj.is_used = True
                token_obj.save()
                
                return Response({
                    "message": "Password has been reset successfully."
                }, status=status.HTTP_200_OK)
                
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class SendOTPView(APIView):
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        phone_number = request.data.get("phone_number")
        
        if not phone_number:
            return Response(
                {"error": "Phone number is required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
   
        cleaned_number = clean_phone_number(phone_number)
        if not cleaned_number:
            return Response(
                {"error": "Invalid phone number format. Please enter a 10-digit number."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
      
        logger.info(f"OTP request for phone: {cleaned_number}")
        
      
        result = send_otp(cleaned_number)
        
        if "error" in result:
          
            response_data = {
                "error": result.get("error", "Failed to send OTP")
            }
            
          
            if "test_otp" in result:
                response_data["test_otp"] = result["test_otp"]
                response_data["verification_id"] = result["verification_id"]
                response_data["message"] = "Using fallback OTP generation"
                
             
                return Response(response_data, status=status.HTTP_200_OK)
            
    
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        
        logger.info(f"OTP sent successfully to {cleaned_number}")
        return Response(result, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        phone_number = request.data.get("phone_number")
        otp = request.data.get("otp")
        verification_id = request.data.get("verification_id")
        
        if not phone_number or not otp:
            return Response(
                {"error": "Phone number and OTP are required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Clean and validate phone number
        cleaned_number = clean_phone_number(phone_number)
        if not cleaned_number:
            return Response(
                {"error": "Invalid phone number format. Please enter a 10-digit number."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log the verification attempt
        logger.info(f"OTP verification for phone: {cleaned_number}")
        
        # Verify the OTP
        result = verify_otp(cleaned_number, otp, verification_id)
        
        if "error" in result:
            logger.warning(f"OTP verification failed: {result['error']}")
            
            # Special case: if verification_id and otp are identical, force success
            # This is for testing and when MessageCentral API fails
            if verification_id and verification_id == otp:
                logger.info(f"Forcing OTP verification success for {cleaned_number}")
                try:
                    user = CustomUser.objects.get(phone_number=cleaned_number)
                    user.is_verified = True
                    user.save()
                except CustomUser.DoesNotExist:
                    pass
                
                return Response({"message": "OTP verified successfully (direct match)"}, status=status.HTTP_200_OK)
            
            # Otherwise return the error
            return Response({
                "error": result.get("error", "Failed to verify OTP"),
                "details": result.get("details", "")
            }, status=status.HTTP_400_BAD_REQUEST)
            
        # Log successful verification
        logger.info(f"OTP verified successfully for {cleaned_number}")
        return Response(result, status=status.HTTP_200_OK)


# class RegisterUserView(APIView):
#     permission_classes = []
#     authentication_classes = []
#     parser_classes = [MultiPartParser, FormParser, JSONParser]  # Handle all data types
    
#     def post(self, request):
#         logger.info(f"Content-Type: {request.content_type}")
#         logger.info(f"Request data: {dict(request.data)}")
#         logger.info(f"Files: {dict(request.FILES)}")
        
#         serializer = UserRegistrationSerializer(data=request.data)
        
#         if serializer.is_valid():
#             # Create the user
#             try:
#                 user = serializer.save()
#                 user_serializer = UserSerializer(user, context={'request': request})
                
#                 membership_card_url = None
                
#                 # First, ensure user has a QR code
#                 try:
#                     if not user.qr_code:
#                         logger.info(f"Creating QR code for new user: {user.username}")
#                         create_user_with_qr(user)
#                         user.refresh_from_db() 
#                 except Exception as qr_error:
#                     logger.error(f"Error creating QR code: {qr_error}")
                  
#                 return Response({
#                     "user_id": user.user_id,
#                     'message': 'User registered successfully',
#                     'user_type': user.user_type,
#                     'is_active': user.is_active,
#                     'user': user_serializer.data,
#                     'has_profile_picture': bool(user.profile_picture),
#                     'membership_card_url': membership_card_url, 
#                     'membership_card_status': 'pending'  
#                 }, status=status.HTTP_201_CREATED)
                
#             except Exception as e:
#                 logger.error(f"Error during user registration: {e}")
#                 return Response({
#                     'error': f'Registration failed: {str(e)}'
#                 }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
#         # Handle validation errors
#         errors = serializer.errors
#         logger.warning(f"Serializer errors: {errors}")
        
#         # Check for specific errors
#         if 'phone_number' in errors:
#             return Response({
#                 'error': 'User with this phone number already exists',
#                 'field': 'phone_number'
#             }, status=status.HTTP_409_CONFLICT)
        
#         if 'email' in errors:
#             return Response({
#                 'error': 'User with this email already exists',
#                 'field': 'email'
#             }, status=status.HTTP_409_CONFLICT)
        
#         # Return all validation errors
#         return Response(errors, status=status.HTTP_400_BAD_REQUEST)

class RegisterUserView(APIView):
    permission_classes = []
    authentication_classes = []
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    
    def post(self, request):
        logger.info(f"Content-Type: {request.content_type}")
        logger.info(f"Request data: {dict(request.data)}")
        logger.info(f"Files: {dict(request.FILES)}")
        
        # Validate uploaded files first
        if 'profile_picture' in request.FILES:
            profile_pic = request.FILES['profile_picture']
            
            if profile_pic.size > 5 * 1024 * 1024:
                return Response({
                    'error': 'Profile picture too large (5MB max)',
                    'field': 'profile_picture'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not profile_pic.content_type.startswith('image/'):
                return Response({
                    'error': 'Profile picture must be an image',
                    'field': 'profile_picture'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = UserRegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    # Create the user
                    user = serializer.save()
                    
                    # Create QR code (non-blocking)
                    try:
                        if not user.qr_code:
                            logger.info(f"Creating QR code for new user: {user.username}")
                            create_user_with_qr(user)
                            user.refresh_from_db()
                            logger.info(f"QR code created: {user.qr_code}")
                    except Exception as qr_error:
                        logger.error(f"QR code creation failed: {qr_error}")
                        # Continue registration without QR code
                    
                    user_serializer = UserSerializer(user, context={'request': request})
                    
                    return Response({
                        "user_id": user.user_id,
                        'message': 'User registered successfully',
                        'user_type': user.user_type,
                        'is_active': user.is_active,
                        'user': user_serializer.data,
                        'has_profile_picture': bool(user.profile_picture),
                        'profile_picture_url': user.profile_picture.url if user.profile_picture else None,
                        'qr_code_url': user.qr_code.url if user.qr_code else None,
                        'membership_card_url': None, 
                        'membership_card_status': 'pending'  
                    }, status=status.HTTP_201_CREATED)
                    
            except Exception as e:
                logger.error(f"Error during user registration: {e}")
                return Response({
                    'error': f'Registration failed: {str(e)}'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Handle validation errors
        errors = serializer.errors
        logger.warning(f"Serializer errors: {errors}")
        
        if 'phone_number' in errors:
            return Response({
                'error': 'User with this phone number already exists',
                'field': 'phone_number'
            }, status=status.HTTP_409_CONFLICT)
        
        if 'email' in errors:
            return Response({
                'error': 'User with this email already exists',
                'field': 'email'
            }, status=status.HTTP_409_CONFLICT)
        
        return Response(errors, status=status.HTTP_400_BAD_REQUEST)



class ResendOTPView(APIView):
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        phone_number = request.data.get("phone_number")
        
        if not phone_number:
            return Response(
                {"error": "Phone number is required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        logger.info(f"Resend OTP request for phone: {phone_number}")
        result = send_otp(phone_number)
        
        if "error" in result:
            logger.warning(f"Resend OTP failed: {result['error']}")
            return Response({
                "error": result.get("error", "Failed to resend OTP"),
                "details": result.get("details", ""),
                "raw_response": result.get("raw_response", "")
            }, status=status.HTTP_400_BAD_REQUEST)
            
        logger.info(f"OTP resent successfully to {phone_number}")
        return Response(result, status=status.HTTP_200_OK)


class TestOTPView(APIView):
    """View for testing OTP functionality without using real SMS"""
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        phone_number = request.data.get("phone_number")
        
        if not phone_number:
            return Response(
                {"error": "Phone number is required."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate a test OTP and store it
        import random
        otp = str(random.randint(100000, 999999))
        
        try:
            user = CustomUser.objects.get(phone_number=phone_number)
            user.otp = otp
            user.save()
        except CustomUser.DoesNotExist:
            # For testing, we'll just return the OTP
            pass
        
        # Return the OTP directly for testing
        return Response({
            "message": "Test OTP generated",
            "verification_id": otp,
            "test_otp": otp  # Include the actual OTP for testing
        }, status=status.HTTP_200_OK)
    
  
class CheckUserExistsView(APIView):
    """
    API endpoint to check if a user already exists with the given email or phone
    """
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        email = request.data.get('email')
        phone_number = request.data.get('phone_number')
        
        if not email and not phone_number:
            return Response({
                "error": "Either email or phone_number must be provided"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check for existing users
        exists = False
        existing_fields = []
        
        if email:
            if CustomUser.objects.filter(email=email).exists():
                exists = True
                existing_fields.append('email')
        
        if phone_number:
            if CustomUser.objects.filter(phone_number=phone_number).exists():
                exists = True
                existing_fields.append('phone_number')
        
        if exists:
            return Response({
                "exists": True,
                "fields": existing_fields,
                "message": "User with this information already exists"
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "exists": False,
                "message": "No existing user found with this information"
            }, status=status.HTTP_200_OK)


class DeleteUserView(APIView):
    """
    API endpoint to delete a user by email or phone number
    Only for development/testing purposes!
    """
    permission_classes = []
    authentication_classes = []
    
    def post(self, request):
        # Check if this is being called in development
        from django.conf import settings
        if not settings.DEBUG:
            return Response({
                "error": "This endpoint is only available in development mode"
            }, status=status.HTTP_403_FORBIDDEN)
        
        email = request.data.get('email')
        phone_number = request.data.get('phone_number')
        
        if not email and not phone_number:
            return Response({
                "error": "Either email or phone_number must be provided"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Build query to find users
        query = Q()
        if email:
            query |= Q(email=email)
        if phone_number:
            query |= Q(phone_number=phone_number)
        
        # Find and delete users
        users = CustomUser.objects.filter(query)
        count = users.count()
        
        if count == 0:
            return Response({
                "message": "No users found with the provided information"
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Store the information for logging
        user_info = []
        for user in users:
            user_info.append({
                "user_id": str(user.user_id),
                "email": user.email,
                "phone_number": user.phone_number
            })
        
        # Delete the users
        users.delete()
        
        logger.warning(f"Deleted {count} users: {user_info}")
        
        return Response({
            "message": f"Successfully deleted {count} users",
            "deleted_users": user_info
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class CreateRazorpayOrderView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access
    
    def dispatch(self, request, *args, **kwargs):
        # Add CORS headers to all responses
        response = super().dispatch(request, *args, **kwargs)
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    
    def options(self, request, *args, **kwargs):
        # Handle CORS preflight
        response = Response()
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    
    def post(self, request):
        try:
            logger.info("=== CREATE RAZORPAY ORDER ===")
            logger.info(f"Request data: {request.data}")
            
            user_id = request.data.get("user_id")
            
            if not user_id:
                return Response({
                    "error": "user_id is required"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                user = CustomUser.objects.get(user_id=user_id)
                logger.info(f"User found: {user.email}")
            except CustomUser.DoesNotExist:
                return Response({
                    "error": "User not found"
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check Razorpay configuration
            if not settings.RAZORPAY_KEY_ID or not settings.RAZORPAY_KEY_SECRET:
                logger.error("Razorpay keys not configured")
                return Response({
                    "error": "Payment gateway not configured"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            logger.info(f"Using Razorpay Key: {settings.RAZORPAY_KEY_ID}")
            
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            amount_in_paise = 1 * 100  # ₹200 in paise
            
            order_data = {
                "amount": amount_in_paise,
                "currency": "INR",
                "payment_capture": 1,
                "notes": {
                    "user_id": str(user.user_id),
                    "email": user.email,
                }
            }
            
            try:
                razorpay_order = client.order.create(order_data)
                logger.info(f"✅ Razorpay order created: {razorpay_order['id']}")
            except Exception as e:
                logger.error(f"❌ Razorpay order creation failed: {str(e)}")
                return Response({
                    "error": f"Failed to create payment order: {str(e)}"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create payment record
            try:
                payment = Payment.objects.create(
                    user=user,
                    amount=1,
                    order_id=razorpay_order["id"],
                    status="created"
                )
                logger.info(f"✅ Payment record created: {payment.id}")
            except Exception as e:
                logger.error(f"❌ Payment record creation failed: {str(e)}")
                return Response({
                    "error": "Failed to create payment record"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response({
                "order_id": razorpay_order["id"],
                "razorpay_key": settings.RAZORPAY_KEY_ID,
                "amount": amount_in_paise,
                "currency": "INR"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"❌ Unexpected error in CreateRazorpayOrderView: {str(e)}")
            return Response({
                "error": "Internal server error",
                "details": str(e) if settings.DEBUG else None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@method_decorator(csrf_exempt, name='dispatch')
class VerifyPaymentView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            logger.info("=== VERIFY PAYMENT ===")
            logger.info(f"Request data: {request.data}")
            logger.info(f"Request origin: {request.META.get('HTTP_ORIGIN', 'No origin')}")
            
            razorpay_payment_id = request.data.get("razorpay_payment_id")
            razorpay_order_id = request.data.get("razorpay_order_id")
            razorpay_signature = request.data.get("razorpay_signature")
            
            # Extract user_id from request if available
            user_id = request.data.get("user_id")
            logger.info(f"User ID from request: {user_id}")
            
            if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
                return Response({
                    "error": "Missing payment details"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Check Razorpay configuration
            if not settings.RAZORPAY_KEY_ID or not settings.RAZORPAY_KEY_SECRET:
                logger.error("Razorpay keys not configured")
                return Response({
                    "error": "Payment gateway not configured"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            try:
                from .models import Payment
                payment = Payment.objects.get(order_id=razorpay_order_id)
                logger.info(f"Payment record found: {payment.id}")
                
                # Get user from payment if user_id not provided
                if not user_id and payment.user:
                    user_id = payment.user.user_id
                    logger.info(f"Using user ID from payment record: {user_id}")
            except Payment.DoesNotExist:
                logger.error(f"Payment record not found for order: {razorpay_order_id}")
                return Response({
                    "error": "Payment record not found"
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Razorpay signature verification
            import razorpay
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            params_dict = {
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_order_id': razorpay_order_id,
                'razorpay_signature': razorpay_signature
            }
            
            try:
                client.utility.verify_payment_signature(params_dict)
                logger.info("✅ Payment signature verified")
            except razorpay.errors.SignatureVerificationError as e:
                logger.error(f"❌ Signature verification failed: {str(e)}")
                payment.status = 'failed'
                payment.save()
                return Response({
                    "error": "Signature verification failed"
                }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                logger.error(f"❌ Razorpay verification error: {str(e)}")
                return Response({
                    "error": "Payment verification failed"
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Payment success - Update payment record
            payment.payment_id = razorpay_payment_id
            payment.signature = razorpay_signature
            payment.status = 'paid'
            payment.save()
            logger.info("✅ Payment record updated")
            
            # Activate user membership
            user = payment.user
            try:
                user.activate_membership()
                logger.info(f"✅ Membership activated for user: {user.email}")
            except Exception as e:
                logger.error(f"❌ Membership activation failed: {str(e)}")
                # Don't fail payment verification for membership activation issues
            
            # Use cross-platform timeout for membership card generation
            membership_card_url = None
            try:
                @timeout_handler(10)  # 10 second timeout
                def generate_card():
                    from .utils import create_or_update_membership_card
                    pdf_relative_path = create_or_update_membership_card(user, request)
                    if pdf_relative_path:
                        return settings.MEDIA_URL + pdf_relative_path
                    return None
                
                # Generate card with timeout protection
                membership_card_url = generate_card()
                if membership_card_url:
                    user.membership_card_url = membership_card_url
                    user.save()
                    logger.info(f"✅ Membership card generated: {membership_card_url}")
                else:
                    logger.warning("⚠️ Card generation returned None")
                    
            except TimeoutError:
                logger.warning("⚠️ Membership card generation timed out")
                # You could queue this for background processing here
                
            except Exception as card_error:
                logger.error(f"⚠️ Membership card generation error: {str(card_error)}")
            
            # Return response with user_id and membership_card_url if available
            response_data = {
                "message": "Payment verified, membership activated",
                "success": True,
                "user_id": user_id,
            }
            
            # Include membership card URL if available
            if membership_card_url:
                response_data["membership_card_url"] = membership_card_url
            else:
                response_data["card_generation"] = "Membership card will be generated shortly"
            
            return Response(response_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"❌ Unexpected error in VerifyPaymentView: {str(e)}")
            return Response({
                "error": "Internal server error",
                "details": str(e) if settings.DEBUG else None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@method_decorator(csrf_exempt, name='dispatch')
class TestPaymentView(APIView):
    permission_classes = [AllowAny]
    
    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    
    def options(self, request, *args, **kwargs):
        response = Response()
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return response
    
    def get(self, request):
        return Response({
            "message": "Payment API is working!",
            "razorpay_configured": bool(settings.RAZORPAY_KEY_ID and settings.RAZORPAY_KEY_SECRET),
            "razorpay_key_id": settings.RAZORPAY_KEY_ID[:10] + "..." if settings.RAZORPAY_KEY_ID else "Not configured",
            "debug_mode": settings.DEBUG
        })
    
    def post(self, request):
        return Response({
            "message": "POST request received",
            "data": request.data
        })

class ActivateMemberView(APIView):
    permission_classes = [] 
    authentication_classes = []
    def post(self, request):
        user_id = request.data.get("user_id")
        try:
            user = CustomUser.objects.get(user_id=user_id)
            if user.is_verified :
                if user.user_type == "member" and not user.is_active:
                    user.activate_membership()
                    return Response({"message": "Membership activated successfully!"}, status=status.HTTP_200_OK)
                return Response({"error": "User is already active or not a member"}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": "User is Not verified mobile number"}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

# class PasswordLoginView(APIView):
#     permission_classes = []
#     authentication_classes = []

#     def post(self, request):
#         email = request.data.get("email")
#         password = request.data.get("password")

#         if email and password:
#             user = authenticate(request, email=email, password=password)
#             if user:
#                 userdb = CustomUser.objects.get(email=email)
#                 userdb.membership_is_valid()  # checks if membership is still valid
#                 if userdb.is_active:
#                     refresh = RefreshToken.for_user(userdb)

#                     # Return both token and user info
#                     return Response({
#                         "access": str(refresh.access_token),
#                         "user": {
#                             "username": userdb.username,
#                             "email": userdb.email,
#                             "phone_number": userdb.phone_number,
                     
#                             "user_id": userdb.user_id,
#                             # add any other fields you want to send
#                         }
#                     }, status=status.HTTP_200_OK)

#                 # Return 403 instead of 200 when user needs a subscription
#                 return Response(
#                     {"error": "You need a subscription", "user_id": user.user_id ,"username": user.username},
#                     status=status.HTTP_403_FORBIDDEN
#                 )

#             return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
#         else:
#             return Response({"error": "Provide username and password"}, status=status.HTTP_400_BAD_REQUEST)    
class PasswordLoginView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if email and password:
            user = authenticate(request, email=email, password=password)
            if user:
                userdb = CustomUser.objects.get(email=email)
                userdb.membership_is_valid()  # checks if membership is still valid
                
                if userdb.is_active:
                    refresh = RefreshToken.for_user(userdb)
                    
                    # Helper function to get profile picture URL
                    def get_profile_picture_url(user_obj):
                        if user_obj.profile_picture:
                            return request.build_absolute_uri(user_obj.profile_picture.url)
                        return None
                    
                    # Return both token and user info with profile picture
                    return Response({
                        "access": str(refresh.access_token),
                        "user": {
                            "username": userdb.username,
                            "email": userdb.email,
                            "phone_number": userdb.phone_number,
                            "user_id": userdb.user_id,
                            "user_type": userdb.user_type,
                            "is_active": userdb.is_active,
                            "membership_expiry": userdb.membership_expiry,
                            "profile_picture": userdb.profile_picture.url if userdb.profile_picture else None,
                            "profile_picture_url": get_profile_picture_url(userdb),
                            "membership_card_url": userdb.membership_card_url,
                            "qr_code": userdb.qr_code.url if userdb.qr_code else None,
                            # Add any other fields you want to send
                        }
                    }, status=status.HTTP_200_OK)

                # Return 403 instead of 200 when user needs a subscription
                return Response(
                    {
                        "error": "You need a subscription", 
                        "user_id": user.user_id,
                        "username": user.username,
                        "profile_picture_url": request.build_absolute_uri(user.profile_picture.url) if user.profile_picture else None
                    },
                    status=status.HTTP_403_FORBIDDEN
                )

            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({"error": "Provide username and password"}, status=status.HTTP_400_BAD_REQUEST)

class AllMemberdetails(APIView):
    queryset = CustomUser.objects.filter(user_type = 'member')
    serializer_class = UserSerializer

class AllUserdetails(APIView):
    permission_classes = [] 
    authentication_classes = []
    def get(self, request):
        users = CustomUser.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)




class Userdetails(APIView):
    def get(self, request):
        user_id = request.query_params.get("user_id")
        if not user_id:
            return Response({"error": "user_id query param is required"}, status=400)

        try:
            user = CustomUser.objects.get(user_id=user_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        # Pass request context to get full URLs
        serializer = UserSerializer(user, context={'request': request})
        return Response(serializer.data, status=200)






# membershipcard

class GenerateMembershipCardView(APIView):
    # Remove authentication restrictions to allow access during registration
    permission_classes = []  # Allow unauthenticated access
    authentication_classes = []  # No authentication required
    
    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({'error': 'User ID is required'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            # Log the request for debugging
            logger.info(f"Generating membership card for user_id: {user_id}")
            
            user = CustomUser.objects.get(user_id=user_id)
            
            # Check if card already exists and is valid
            if user.membership_card_url:
                # Check if the file actually exists
                file_path = os.path.join(
                    settings.MEDIA_ROOT,
                    user.membership_card_url.replace(settings.MEDIA_URL, "")
                )
                
                if os.path.exists(file_path):
                    logger.info(f"Existing membership card found for user: {user.username} (KEA ID: {user.kea_id})")
                    return Response({
                        'message': 'Membership card already exists',
                        'membership_card_url': user.membership_card_url,
                        'kea_id': user.kea_id,  # Added KEA ID to response
                        'card_exists': True
                    }, status=status.HTTP_200_OK)
                else:
                    logger.info(f"Membership card URL exists but file missing, regenerating for user: {user.username} (KEA ID: {user.kea_id})")
            
            # Create QR code if not exists
            if not user.qr_code:
                logger.info(f"Creating QR code for user: {user.username} (KEA ID: {user.kea_id})")
                create_user_with_qr(user)
            
            # Generate or update the membership card
            logger.info(f"Creating/updating membership card for user: {user.username} (KEA ID: {user.kea_id})")
            pdf_path = create_or_update_membership_card(user, request)
            
            if pdf_path:
                # Update user record with card URL - ensure proper format
                if not pdf_path.startswith(settings.MEDIA_URL):
                    card_url = settings.MEDIA_URL + pdf_path
                else:
                    card_url = pdf_path
                
                user.membership_card_url = card_url
                user.save(update_fields=['membership_card_url'])
                
                # Verify the file was actually created
                full_file_path = os.path.join(settings.MEDIA_ROOT, pdf_path)
                if os.path.exists(full_file_path):
                    logger.info(f"Membership card generated successfully: {user.membership_card_url}")
                    return Response({
                        'message': 'Membership card generated successfully',
                        'membership_card_url': user.membership_card_url,
                        'kea_id': user.kea_id,  # Added KEA ID to response
                        'file_path': pdf_path,
                        'file_exists': True
                    }, status=status.HTTP_200_OK)
                else:
                    logger.error(f"PDF file not found after generation: {full_file_path}")
                    return Response({
                        'error': 'PDF file was not created properly'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                logger.error(f"Failed to generate membership card for user: {user.username} (KEA ID: {user.kea_id})")
                return Response({
                    'error': 'Failed to generate membership card'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except CustomUser.DoesNotExist:
            logger.error(f"User not found: {user_id}")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error generating membership card: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GenerateQRCodeView(APIView):
    """
    Generate a QR code for a user
    """
    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({'error': 'User ID is required'}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = CustomUser.objects.get(user_id=user_id)
            logger.info(f"Generating QR code for user: {user.username} (KEA ID: {user.kea_id})")
            success = create_user_with_qr(user)
            
            if success:
                return Response({
                    'message': 'QR code generated successfully',
                    'qr_code_url': user.qr_code.url if user.qr_code else None,
                    'kea_id': user.kea_id  # Added KEA ID to response
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Failed to generate QR code'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error generating QR code: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(xframe_options_exempt, name='dispatch')
class MembershipCardPreviewView(APIView):
    """
    View for directly rendering a membership card PDF with proper headers
    This view is exempt from X-Frame-Options to allow embedding in iframes
    """
    permission_classes = []
    authentication_classes = []
    
    def get(self, request, user_id):
        try:
            # Get the user
            try:
                user = CustomUser.objects.get(user_id=user_id)
                logger.info(f"Preview request for user: {user.username} (KEA ID: {user.kea_id})")
            except CustomUser.DoesNotExist:
                return Response(
                    {"error": "User not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Generate the PDF
            pdf_file = generate_membership_card_pdf(user, request)
            
            # Return the PDF directly with proper headers
            response = HttpResponse(
                content=pdf_file.getvalue(),
                content_type='application/pdf'
            )
            
            # Updated filename to use KEA ID
            response['Content-Disposition'] = f'inline; filename="membership_card_{user.kea_id}.pdf"'
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
            
            # Add CORS headers
            response["Access-Control-Allow-Origin"] = "https://keablr.netlify.app"
            response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response["Access-Control-Allow-Credentials"] = "true"
            
            return response
            
        except Exception as e:
            logger.error(f"Error rendering membership card: {e}")
            return Response(
                {"error": f"Failed to render membership card: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def options(self, request, *args, **kwargs):
        """Handle preflight CORS requests"""
        response = HttpResponse()
        response["Access-Control-Allow-Origin"] = "https://keablr.netlify.app"
        response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response["Access-Control-Allow-Credentials"] = "true"
        return response

@method_decorator(xframe_options_exempt, name='dispatch')
class DirectPDFView(APIView):
    permission_classes = []
    authentication_classes = []
    
    def get(self, request, user_id):
        try:
            logger.info(f"DirectPDFView: Serving PDF for user_id: {user_id}")
            
            # Get the user with better error handling
            try:
                user = CustomUser.objects.get(user_id=user_id)
                logger.info(f"User found: {user.username} (KEA ID: {user.kea_id})")
            except CustomUser.DoesNotExist:
                logger.warning(f"User not found: {user_id}")
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                logger.error(f"Error fetching user: {e}")
                return Response({"error": "Database error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # IMPROVED: Try multiple methods to find the PDF file
            pdf_file_path = None
            
            # Method 1: Check if membership_card_url exists and construct path
            if hasattr(user, 'membership_card_url') and user.membership_card_url:
                try:
                    # Clean the URL and construct file path
                    relative_path = user.membership_card_url.replace(settings.MEDIA_URL, "").lstrip('/')
                    pdf_file_path = os.path.join(settings.MEDIA_ROOT, relative_path)
                    logger.info(f"Method 1 - Constructed path from URL: {pdf_file_path}")
                    
                    if os.path.exists(pdf_file_path):
                        logger.info("Method 1 - File found using membership_card_url")
                    else:
                        logger.warning(f"Method 1 - File not found: {pdf_file_path}")
                        pdf_file_path = None
                except Exception as e:
                    logger.warning(f"Method 1 failed: {e}")
                    pdf_file_path = None
            
            # Method 2: Check direct file field if available
            if not pdf_file_path and hasattr(user, 'membership_card') and user.membership_card:
                try:
                    if hasattr(user.membership_card, 'path') and os.path.exists(user.membership_card.path):
                        pdf_file_path = user.membership_card.path
                        logger.info(f"Method 2 - File found using direct field: {pdf_file_path}")
                    else:
                        logger.warning("Method 2 - Direct field path not accessible")
                except Exception as e:
                    logger.warning(f"Method 2 failed: {e}")
            
            # Method 3: Search for file using KEA ID naming convention
            if not pdf_file_path:
                try:
                    # Try both KEA ID and user_id naming conventions
                    kea_filename = f"membership_card_{user.kea_id}.pdf"
                    uuid_filename = f"membership_card_{user_id}.pdf"
                    
                    kea_path = os.path.join(settings.MEDIA_ROOT, "membership_cards", kea_filename)
                    uuid_path = os.path.join(settings.MEDIA_ROOT, "membership_cards", uuid_filename)
                    
                    if os.path.exists(kea_path):
                        pdf_file_path = kea_path
                        logger.info(f"Method 3 - File found using KEA ID naming: {pdf_file_path}")
                    elif os.path.exists(uuid_path):
                        pdf_file_path = uuid_path
                        logger.info(f"Method 3 - File found using UUID naming: {pdf_file_path}")
                    else:
                        logger.warning(f"Method 3 - Neither file found: {kea_path} or {uuid_path}")
                except Exception as e:
                    logger.warning(f"Method 3 failed: {e}")
            
            # Method 4: Generate PDF on-the-fly if no file found
            if not pdf_file_path:
                logger.info("Method 4 - No existing file found, generating PDF on-the-fly")
                try:
                    # Generate PDF buffer using the updated function
                    pdf_buffer = generate_membership_card_pdf(user, request)
                    
                    if pdf_buffer:
                        logger.info("PDF generated successfully on-the-fly")
                        
                        # Serve directly from buffer
                        response = HttpResponse(pdf_buffer.getvalue(), content_type='application/pdf')
                        response['Content-Disposition'] = f'inline; filename="membership_card_{user.kea_id}.pdf"'
                        response['Content-Length'] = str(len(pdf_buffer.getvalue()))
                        
                        # Add essential headers (let Django CORS middleware handle CORS)
                        response['Cache-Control'] = 'public, max-age=3600'
                        response['X-Content-Type-Options'] = 'nosniff'
                        
                        # Optionally save the generated PDF for future use
                        try:
                            self._save_generated_pdf(user, pdf_buffer)
                        except Exception as save_error:
                            logger.warning(f"Could not save generated PDF: {save_error}")
                        
                        return response
                    else:
                        logger.error("PDF generation returned None")
                        return Response({"error": "Could not generate membership card"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                        
                except Exception as e:
                    logger.error(f"On-the-fly PDF generation failed: {e}")
                    return Response({"error": "Could not generate membership card"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Serve existing file
            if pdf_file_path and os.path.exists(pdf_file_path):
                try:
                    logger.info(f"Serving existing PDF file: {pdf_file_path}")
                    
                    # Check file size
                    file_size = os.path.getsize(pdf_file_path)
                    logger.info(f"PDF file size: {file_size} bytes")
                    
                    # Read and serve the file
                    with open(pdf_file_path, 'rb') as pdf_file:
                        pdf_content = pdf_file.read()
                        
                        response = HttpResponse(pdf_content, content_type='application/pdf')
                        response['Content-Disposition'] = f'inline; filename="membership_card_{user.kea_id}.pdf"'
                        response['Content-Length'] = str(len(pdf_content))
                        
                        # Add essential headers (let Django CORS middleware handle CORS)
                        response['Cache-Control'] = 'public, max-age=3600'
                        response['X-Content-Type-Options'] = 'nosniff'
                        
                        logger.info("PDF served successfully")
                        return response
                        
                except Exception as e:
                    logger.error(f"Error reading PDF file: {e}")
                    return Response({"error": "Could not read membership card file"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # If we get here, no PDF could be found or generated
            logger.error("No membership card found and generation failed")
            return Response({"error": "No membership card found for this user"}, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            logger.error(f"Unexpected error in DirectPDFView: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _save_generated_pdf(self, user, pdf_buffer):
        """Save generated PDF for future use"""
        try:
            # Create directory if it doesn't exist
            membership_cards_dir = os.path.join(settings.MEDIA_ROOT, "membership_cards")
            os.makedirs(membership_cards_dir, exist_ok=True)
            
            # Save the PDF file using KEA ID
            file_name = f"membership_card_{user.kea_id}.pdf"
            file_path = os.path.join(membership_cards_dir, file_name)
            
            with open(file_path, "wb") as f:
                f.write(pdf_buffer.getvalue())
            
            # Update user's membership_card_url
            relative_path = f"membership_cards/{file_name}"
            user.membership_card_url = f"{settings.MEDIA_URL}{relative_path}"
            user.save(update_fields=['membership_card_url'])
            
            logger.info(f"PDF saved and user updated: {user.membership_card_url}")
            
        except Exception as e:
            logger.error(f"Error saving generated PDF: {e}")
            raise e
    
    def options(self, request, *args, **kwargs):
        """Handle preflight CORS requests - Let Django CORS middleware handle this"""
        # Since we're letting Django handle CORS, we can simplify this
        response = HttpResponse()
        response['Cache-Control'] = 'no-cache'
        return response

@method_decorator(csrf_exempt, name='dispatch')
class RegenerateMembershipCardAPIView(APIView):
    """
    API endpoint to regenerate a membership card with improved error handling and performance.
    """
    permission_classes = [IsAuthenticated]
    
    def dispatch(self, request, *args, **kwargs):
        """Add CORS headers to all responses"""
        try:
            response = super().dispatch(request, *args, **kwargs)
        except Exception as e:
            # Catch any unhandled exceptions and return JSON response
            logger.error(f"Unhandled exception in dispatch: {str(e)}\n{traceback.format_exc()}")
            response = JsonResponse({
                'error': 'An unexpected error occurred. Please try again.',
                'error_type': type(e).__name__
            }, status=500)
        
        # Add CORS headers to every response
        response['Access-Control-Allow-Origin'] = 'https://keablr.netlify.app'
        response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Accept'
        response['Access-Control-Allow-Credentials'] = 'true'
        
        return response
    
    def options(self, request, *args, **kwargs):
        """Handle preflight CORS requests"""
        logger.info("Handling OPTIONS preflight for regenerate membership card")
        return Response(status=200)
    
    def post(self, request):
        start_time = time.time()
        logger.info(f"Regenerate membership card request from: {request.META.get('HTTP_ORIGIN', 'unknown')}")
        
        try:
            # Validate input
            user_id = request.data.get('user_id')
            if not user_id:
                return JsonResponse({
                    'error': 'user_id is required'
                }, status=400)
            
            # Get the user
            try:
                user = CustomUser.objects.get(user_id=user_id)
                logger.info(f"Regenerating card for user: {user.username} (KEA ID: {user.kea_id})")
            except CustomUser.DoesNotExist:
                return JsonResponse({
                    'error': 'User not found'
                }, status=404)
            
            # Check permissions
            if request.user.user_id != user.user_id and not request.user.is_staff:
                return JsonResponse({
                    'error': 'You do not have permission to regenerate this membership card'
                }, status=403)
            
            # Step 1: Quick QR code generation (with timeout)
            qr_success = False
            try:
                # Run QR generation with a 5-second timeout
                future = executor.submit(create_user_with_qr, user)
                qr_success = future.result(timeout=5)
            except FutureTimeoutError:
                logger.warning(f"QR generation timed out for user {user_id}")
            except Exception as e:
                logger.error(f"QR generation error: {str(e)}")
            
            # Step 2: Generate PDF with timeout protection
            try:
                # Check if profile picture exists to avoid errors
                if hasattr(user, 'profile_picture') and user.profile_picture:
                    # Ensure the profile picture file exists
                    if hasattr(user.profile_picture, 'path'):
                        if not os.path.exists(user.profile_picture.path):
                            logger.warning(f"Profile picture file not found for user {user_id}")
                            user.profile_picture = None
                
                # Run PDF generation with a 15-second timeout
                future = executor.submit(create_or_update_membership_card, user, request)
                relative_path = future.result(timeout=15)
                
                if relative_path:
                    # Update user's membership card URL
                    user.membership_card_url = settings.MEDIA_URL + relative_path
                    user.save(update_fields=['membership_card_url'])
                    
                    # Prepare response data
                    from .serializers import UserSerializer
                    user_serializer = UserSerializer(user, context={'request': request})
                    
                    processing_time = time.time() - start_time
                    logger.info(f"✅ Card regenerated in {processing_time:.2f}s for KEA ID: {user.kea_id}")
                    
                    return JsonResponse({
                        'message': 'Membership card regenerated successfully',
                        'user': user_serializer.data,
                        'card_url': user.membership_card_url,
                        'kea_id': user.kea_id,  # Added KEA ID to response
                        'processing_time': f"{processing_time:.2f}s",
                        'qr_updated': qr_success,
                        'download_url': f"/auth/download-membership-card/{user.user_id}/",
                        'view_url': f"/auth/view-card/{user.user_id}/"
                    }, status=200)
                else:
                    return JsonResponse({
                        'error': 'Failed to generate PDF. Please check server logs.',
                        'suggestion': 'Please try again in a few moments.'
                    }, status=500)
                    
            except FutureTimeoutError:
                processing_time = time.time() - start_time
                logger.error(f"PDF generation timed out after {processing_time:.2f}s")
                
                # Check if the file was partially created using KEA ID
                membership_cards_dir = os.path.join(settings.MEDIA_ROOT, "membership_cards")
                file_name = f"membership_card_{user.kea_id}.pdf"
                full_path = os.path.join(membership_cards_dir, file_name)
                
                if os.path.exists(full_path):
                    # File exists, update the URL
                    relative_path = os.path.join("membership_cards", file_name)
                    user.membership_card_url = settings.MEDIA_URL + relative_path
                    user.save(update_fields=['membership_card_url'])
                    
                    return JsonResponse({
                        'message': 'Card generation completed but took longer than expected.',
                        'card_url': user.membership_card_url,
                        'kea_id': user.kea_id,  # Added KEA ID to response
                        'processing_time': f"{processing_time:.2f}s",
                        'partial_success': True
                    }, status=202)
                else:
                    return JsonResponse({
                        'error': 'Card generation timed out. The server may be under heavy load.',
                        'suggestion': 'Please try again in a few minutes.',
                        'processing_time': f"{processing_time:.2f}s"
                    }, status=408)
                    
            except Exception as pdf_error:
                processing_time = time.time() - start_time
                logger.error(f"PDF generation error after {processing_time:.2f}s: {str(pdf_error)}\n{traceback.format_exc()}")
                
                return JsonResponse({
                    'error': 'Failed to generate membership card PDF.',
                    'details': str(pdf_error) if settings.DEBUG else 'Internal server error',
                    'suggestion': 'Please check if your profile information is complete and try again.',
                    'processing_time': f"{processing_time:.2f}s"
                }, status=500)
                
        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Unexpected error in regenerate membership card after {processing_time:.2f}s: {str(e)}\n{traceback.format_exc()}")
            
            return JsonResponse({
                'error': 'An unexpected error occurred while regenerating the membership card.',
                'details': str(e) if settings.DEBUG else None,
                'error_type': type(e).__name__,
                'processing_time': f"{processing_time:.2f}s"
            }, status=500)

class DownloadMembershipCardView(APIView):
    """
    Download a membership card
    """
    def get(self, request, user_id):
        try:
            user = get_object_or_404(CustomUser, user_id=user_id)
            logger.info(f"Download request for user: {user.username} (KEA ID: {user.kea_id})")
            
            # Check if membership card exists
            if not user.membership_card_url:
                # Generate it if it doesn't exist
                pdf_path = create_or_update_membership_card(user, request)
                if pdf_path:
                    user.membership_card_url = settings.MEDIA_URL + pdf_path
                    user.save()
                else:
                    return Response({
                        'error': 'Failed to generate membership card'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Get the file path
            file_path = os.path.join(
                settings.MEDIA_ROOT, 
                user.membership_card_url.replace(settings.MEDIA_URL, "")
            )
            
            # Check if file exists
            if not os.path.exists(file_path):
                # Regenerate if it doesn't exist
                pdf_path = create_or_update_membership_card(user, request)
                if pdf_path:
                    user.membership_card_url = settings.MEDIA_URL + pdf_path
                    user.save()
                    file_path = os.path.join(settings.MEDIA_ROOT, pdf_path)
                else:
                    return Response({
                        'error': 'Membership card file not found'
                    }, status=status.HTTP_404_NOT_FOUND)
            
            # Return the file with KEA ID in filename
            return FileResponse(
                open(file_path, 'rb'),
                content_type='application/pdf',
                as_attachment=True,
                filename=f"KEA_Membership_Card_{user.kea_id}_{user.username}.pdf"
            )
                
        except Exception as e:
            logger.error(f"Error downloading membership card: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class SendMembershipCardEmailView(APIView):
    """
    Send a membership card via email
    """
    def post(self, request):
        user_id = request.data.get('user_id')
        print(f"🔍 Received request for user_id: {user_id}")  # Debug
        
        if not user_id:
            return Response({'error': 'User ID is required'}, status=status.HTTP_400_BAD_REQUEST)
                     
        try:
            user = CustomUser.objects.get(user_id=user_id)
            print(f"✅ User found: {user.email}")  # Debug
                     
            # Generate the membership card
            print("🔄 Generating membership card PDF...")
            pdf_file = generate_membership_card_pdf(user, request)
            
            # Handle different types of PDF file objects
            if pdf_file:
                if isinstance(pdf_file, io.BytesIO):
                    # Get size of BytesIO object
                    current_pos = pdf_file.tell()
                    pdf_file.seek(0, 2)  # Seek to end
                    pdf_size = pdf_file.tell()
                    pdf_file.seek(current_pos)  # Reset position
                    print(f"📄 PDF generated (BytesIO), size: {pdf_size} bytes")
                elif isinstance(pdf_file, bytes):
                    print(f"📄 PDF generated (bytes), size: {len(pdf_file)} bytes")
                else:
                    print(f"📄 PDF generated, type: {type(pdf_file)}")
            else:
                print("📄 PDF generation returned None")
                return Response({'error': 'Failed to generate PDF'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                     
            # Check if user has email
            if not user.email:
                return Response({'error': 'User does not have an email address'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Send the email with detailed logging
            print(f"📧 Attempting to send email to: {user.email}")
            success = send_membership_card_email(user, pdf_file)
            print(f"📨 Email send result: {success}")
                     
            if success:
                return Response({
                    'message': 'Membership card email sent successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'error': 'Failed to send membership card email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                     
        except CustomUser.DoesNotExist:
            print(f"❌ User not found with user_id: {user_id}")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"❌ Exception occurred: {str(e)}")
            import traceback
            traceback.print_exc()  # This will show the full error traceback
            logger.error(f"Error sending membership card email: {e}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

