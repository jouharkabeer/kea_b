from django.shortcuts import render
from rest_framework import generics , status
from .models import *
from .serializers import *
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework import viewsets, permissions
from .serializers import EventRegistrationSerializer
import razorpay
from django.conf import settings
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from rest_framework.permissions import IsAdminUser
import base64
from io import BytesIO
from rest_framework.permissions import AllowAny
import logging
import jwt
import re
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)
CustomUser = get_user_model()


class Eventview(generics.ListAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [AllowAny]


class EventCreate(generics.ListCreateAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer


class EventUpdate(generics.UpdateAPIView):
    lookup_field = 'event_id'
    queryset = Event.objects.all()
    serializer_class = EventSerializer

class EventDelete(generics.DestroyAPIView):
    lookup_field = 'event_id' 
    queryset = Event.objects.all()
    serializer_class = EventSerializer




class RazorpayOrderAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        event_id = request.data.get('event_id')

        try:
            event = Event.objects.get(event_id=event_id)
            user = request.user
            amount = event.fee_for_member if user.is_active else event.fee_for_external

            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            
            razorpay_order = client.order.create({
                'amount': int(amount * 100),  
                'currency': 'INR',
                'payment_capture': '1'
            })

            return Response({
                'order_id': razorpay_order['id'],
                'amount': amount,
                'currency': 'INR',
                'event_id': event_id,
                'razorpay_key': settings.RAZORPAY_KEY_ID,
            })

        except Event.DoesNotExist:
            return Response({'error': 'Event not found.'}, status=status.HTTP_404_NOT_FOUND)


class EventRegistrationViewSet(viewsets.ModelViewSet):
    serializer_class = EventRegistrationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
       
        if user.is_staff:
            return EventRegistration.objects.all()
        return EventRegistration.objects.filter(registered_by=user)
    

class CheckRegistrationAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        event_id = request.data.get('event_id')
        user = request.user

        if EventRegistration.objects.filter(event__event_id=event_id, registered_by=user).exists():
            return Response({"registered": True, "message": "You have already registered for this event."}, status=status.HTTP_200_OK)
        
        return Response({"registered": False}, status=status.HTTP_200_OK)



  


    
class VerifyUserEventRegistrationAPIView(APIView):
    permission_classes = [IsAdminUser]  

    def post(self, request):
        user_id = request.data.get('user_id')

        try:
            user = CustomUser.objects.get(user_id=user_id)
        except CustomUser.DoesNotExist:
            return Response({"status": "invalid", "message": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)

        current_time = timezone.now()

        registrations = EventRegistration.objects.filter(
            registered_by=user,
            event__event_time__gte=current_time,
            is_active=True
        ).select_related('event')

        if registrations.exists():
            event_details = [
                {
                    'event_name': reg.event.event_name,
                    'event_sub_name': reg.event.event_sub_name,
                    'event_time': reg.event.event_time,
                    'location': reg.event.location,
                    'fee_paid': reg.fee_paid,
                }
                for reg in registrations
            ]

            return Response({
                "status": "registered",
                "user": {
                    "username": user.username,
                    "email": user.email,
                },
                "events": event_details,
            }, status=status.HTTP_200_OK)

        return Response({
            "status": "not_registered",
            "message": "User is not registered for any current events."
        }, status=status.HTTP_200_OK)

def parse_qr_code_data(qr_data):
    """
    Parse the QR code data to extract user_id and other information
    """
    try:
        # Handle new format with KEA_QR prefix
        if qr_data.startswith("KEA_QR|"):
            parts = qr_data.split('|')
            data = {}
            
            for part in parts[1:]:  # Skip the KEA_QR prefix
                if '=' in part:
                    key, value = part.split('=', 1)
                    data[key] = value
            
            return data
        
        # Handle old format (KEA|ID=KEA123|Name=...)
        elif qr_data.startswith("KEA|"):
            parts = qr_data.split('|')
            data = {}
            
            for part in parts[1:]:  # Skip the KEA prefix
                if '=' in part:
                    key, value = part.split('=', 1)
                    data[key] = value
            
            return data
        
        # Unknown format
        return None
    
    except Exception as e:
        logger.error(f"Error parsing QR code data: {e}")
        return None

def decrypt_qr_data(encrypted_b64, encryption_key):
    """
    Decrypt the encrypted data from a QR code.
    """
    # Derive the key using PBKDF2
    salt = b'kea_salt_for_qr_codes'  # Same salt as in generation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(encryption_key.encode()))
    cipher = Fernet(key)
    
    # Decode the base64 encrypted data
    encrypted_data = base64.urlsafe_b64decode(encrypted_b64)
    
    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    
    # Parse the JSON data
    return json.loads(decrypted_data)

class ScanQRForEventCheckInAPIView(APIView):
    """
    Scan user's QR code and verify event registration
    Admin scans the QR code to check if user is registered for a specific event
    """
    permission_classes = [IsAdminUser]
    
    def post(self, request):
        qr_data = request.data.get('qr_data')  
        event_id = request.data.get('event_id')  
        
        if not event_id:
            return Response({
                'status': 'error',
                'message': 'Event ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract user_id from QR data
        user_id = None
        
        if qr_data:
            # Check if this is a secure encrypted QR code
            if qr_data.startswith('KEA_SECURE:'):
                # Extract the JWT token
                jwt_token = qr_data[len('KEA_SECURE:'):]
                
                # Get the JWT secret key from settings
                jwt_secret = getattr(settings, "QR_JWT_SECRET", "your-jwt-secret-for-qr-codes")
                
                try:
                    # Decode and verify the JWT token
                    payload = jwt.decode(jwt_token, jwt_secret, algorithms=['HS256'])
                    
                    # Extract the encrypted data
                    encrypted_b64 = payload.get('data')
                    
                    if not encrypted_b64:
                        return Response({
                            'status': 'error',
                            'message': 'Invalid QR code format: Missing data'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                    # Get encryption key from settings
                    encryption_key = getattr(settings, "QR_ENCRYPTION_KEY", "your-encryption-key-for-qr-codes")
                    
                    try:
                        # Decrypt the data
                        user_data = decrypt_qr_data(encrypted_b64, encryption_key)
                        
                        # Extract the user_id
                        user_id = user_data.get('user_id')
                        
                        if not user_id:
                            return Response({
                                'status': 'error',
                                'message': 'Invalid QR code: No user ID found in decrypted data'
                            }, status=status.HTTP_400_BAD_REQUEST)
                        
                        # Log the successful decryption
                        logger.info(f"Encrypted QR code decrypted successfully. User ID: {user_id}")
                        
                    except Exception as e:
                        logger.error(f"Error decrypting QR code data: {str(e)}")
                        return Response({
                            'status': 'error',
                            'message': 'Invalid QR code. Decryption failed.'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
                except jwt.ExpiredSignatureError:
                    return Response({
                        'status': 'error',
                        'message': 'QR code has expired. Please request a new membership card.'
                    }, status=status.HTTP_400_BAD_REQUEST)
                except jwt.InvalidTokenError as e:
                    logger.error(f"JWT token verification failed: {str(e)}")
                    return Response({
                        'status': 'error',
                        'message': 'Invalid QR code. Unable to verify authenticity.'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Handle other formats (for backward compatibility)
            elif qr_data.startswith('KEA_QR|'):
                parsed_data = {}
                parts = qr_data.split('|')
                
                for part in parts[1:]:  # Skip the KEA_QR prefix
                    if '=' in part:
                        key, value = part.split('=', 1)
                        parsed_data[key] = value
                
                user_id = parsed_data.get('USER_ID')
                
                if not user_id:
                    return Response({
                        'status': 'error',
                        'message': 'Invalid QR code format: No user ID found'
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Handle USER_ID format
            elif 'USER_ID:' in qr_data:
                parts = qr_data.split('USER_ID:')
                if len(parts) > 1:
                    user_id = parts[1].strip().split()[0]  # Get first word after USER_ID:
            
            # Check for UUID format
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', qr_data.strip(), re.IGNORECASE):
                user_id = qr_data.strip()
            
            # Handle direct input (could be just the user_id)
            else:
                user_id = qr_data.strip()
        
        if not user_id:
            return Response({
                'status': 'error',
                'message': 'User ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Rest of your existing code to verify the user and event registration
        try:
            # Get the user from QR scan
            user = CustomUser.objects.get(user_id=user_id)
            
            # Check if user's membership is valid
            if not user.is_active:
                return Response({
                    'status': 'membership_inactive',
                    'message': f'{user.username} has an inactive membership',
                    'user_info': {
                        'username': user.username,
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'membership_expiry': user.membership_expiry,
                        'is_active': user.is_active
                    }
                }, status=status.HTTP_200_OK)
            
            # Check membership expiry
            if user.membership_expiry and user.membership_expiry <= timezone.now():
                return Response({
                    'status': 'membership_expired',
                    'message': f'{user.username} membership has expired',
                    'user_info': {
                        'username': user.username,
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'membership_expiry': user.membership_expiry,
                        'is_active': user.is_active
                    }
                }, status=status.HTTP_200_OK)
            
            # Get the event
            try:
                event = Event.objects.get(event_id=event_id)
            except Event.DoesNotExist:
                return Response({
                    'status': 'event_not_found',
                    'message': 'Event not found'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check if user is registered for this event
            try:
                registration = EventRegistration.objects.get(
                    event=event,
                    registered_by=user,
                    is_active=True
                )
            except EventRegistration.DoesNotExist:
                return Response({
                    'status': 'not_registered',
                    'message': f'{user.username} is not registered for this event',
                    'user_info': {
                        'username': user.username,
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'company_name': user.company_name,
                        'designation': user.designation,
                        'user_type': user.user_type,
                        'membership_expiry': user.membership_expiry
                    },
                    'event_info': {
                        'event_name': event.event_name,
                        'event_sub_name': event.event_sub_name,
                        'event_time': event.event_time,
                        'location': event.location
                    }
                }, status=status.HTTP_200_OK)
            
            # Check if already checked in
            if hasattr(registration, 'checked_in') and registration.checked_in:
                return Response({
                    'status': 'already_checked_in',
                    'message': f'{user.username} is already checked in',
                    'checked_in_at': getattr(registration, 'checked_in_at', None),
                    'user_info': {
                        'username': user.username,
                        'email': user.email,
                        'phone_number': user.phone_number,
                        'company_name': user.company_name,
                        'designation': user.designation,
                        'user_type': user.user_type,
                        'fee_paid': registration.fee_paid
                    },
                    'event_info': {
                        'event_name': event.event_name,
                        'event_sub_name': event.event_sub_name,
                        'location': event.location
                    }
                }, status=status.HTTP_200_OK)
            
            # Success - User is registered and ready for check-in
            return Response({
                'status': 'ready_for_checkin',
                'message': f'{user.username} is registered and ready for check-in',
                'user_info': {
                    'username': user.username,
                    'email': user.email,
                    'phone_number': user.phone_number,
                    'company_name': user.company_name,
                    'designation': user.designation,
                    'department_of_study': user.department_of_study,
                    'year_of_graduation': user.year_of_graduation,
                    'user_type': user.user_type,
                    'fee_paid': registration.fee_paid,
                    'registered_on': registration.registered_on,
                    'profile_picture': user.profile_picture.url if user.profile_picture else None
                },
                'event_info': {
                    'event_name': event.event_name,
                    'event_sub_name': event.event_sub_name,
                    'event_time': event.event_time,
                    'location': event.location,
                    'description': event.description
                },
                'registration_id': str(registration.event_registration_id)
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'user_not_found',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error processing event check-in: {str(e)}")
            return Response({
                'status': 'error',
                'message': f'An error occurred: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ConfirmEventCheckInAPIView(APIView):
    """
    Confirm and complete the check-in process for a user
    """
    permission_classes = [IsAdminUser]
    
    def post(self, request):
        registration_id = request.data.get('registration_id')
        
        if not registration_id:
            return Response({
                'status': 'error',
                'message': 'Registration ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            registration = EventRegistration.objects.get(
                event_registration_id=registration_id,
                is_active=True
            )
            
            # Add checked_in field if it doesn't exist (for backward compatibility)
            if not hasattr(registration, 'checked_in'):
                # You'll need to add this field to your EventRegistration model
                return Response({
                    'status': 'error',
                    'message': 'Check-in functionality not available. Please update your EventRegistration model.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            if registration.checked_in:
                return Response({
                    'status': 'already_checked_in',
                    'message': 'User is already checked in'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Complete the check-in
            registration.checked_in = True
            registration.checked_in_at = timezone.now()
            registration.checked_in_by = request.user
            registration.save()
            
            return Response({
                'status': 'success',
                'message': f'{registration.registered_by.username} has been successfully checked in',
                'checked_in_at': registration.checked_in_at,
                'user_info': {
                    'username': registration.registered_by.username,
                    'email': registration.registered_by.email,
                    'phone_number': registration.registered_by.phone_number,
                    'company_name': registration.registered_by.company_name,
                    'designation': registration.registered_by.designation
                },
                'event_info': {
                    'event_name': registration.event.event_name,
                    'event_sub_name': registration.event.event_sub_name,
                    'location': registration.event.location
                }
            }, status=status.HTTP_200_OK)
            
        except EventRegistration.DoesNotExist:
            return Response({
                'status': 'not_found',
                'message': 'Registration not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'An error occurred: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class EventAttendanceListAPIView(APIView):
    """
    Get attendance list for a specific event
    """
    permission_classes = [IsAdminUser]
    
    def get(self, request, event_id):
        try:
            event = Event.objects.get(event_id=event_id)
            registrations = EventRegistration.objects.filter(
                event=event,
                is_active=True
            ).select_related('registered_by').order_by('-registered_on')
            
            attendance_data = []
            total_registered = registrations.count()
            total_checked_in = 0
            
            for reg in registrations:
                checked_in = getattr(reg, 'checked_in', False)
                if checked_in:
                    total_checked_in += 1
                
                attendance_data.append({
                    'registration_id': str(reg.event_registration_id),
                    'user_id': str(reg.registered_by.user_id),
                    'username': reg.registered_by.username,
                    'email': reg.registered_by.email,
                    'phone_number': reg.registered_by.phone_number,
                    'company_name': reg.registered_by.company_name,
                    'designation': reg.registered_by.designation,
                    'user_type': reg.registered_by.user_type,
                    'registered_on': reg.registered_on,
                    'fee_paid': reg.fee_paid,
                    'checked_in': checked_in,
                    'checked_in_at': getattr(reg, 'checked_in_at', None),
                    'checked_in_by': getattr(reg.checked_in_by, 'username', None) if hasattr(reg, 'checked_in_by') and reg.checked_in_by else None,
                    'profile_picture': reg.registered_by.profile_picture.url if reg.registered_by.profile_picture else None
                })
            
            return Response({
                'event_info': {
                    'event_id': str(event.event_id),
                    'event_name': event.event_name,
                    'event_sub_name': event.event_sub_name,
                    'event_time': event.event_time,
                    'location': event.location,
                    'description': event.description
                },
                'statistics': {
                    'total_registered': total_registered,
                    'total_checked_in': total_checked_in,
                    'pending_checkin': total_registered - total_checked_in,
                    'attendance_rate': f"{(total_checked_in/total_registered*100):.1f}%" if total_registered > 0 else "0%"
                },
                'attendees': attendance_data
            }, status=status.HTTP_200_OK)
            
        except Event.DoesNotExist:
            return Response({
                'status': 'not_found',
                'message': 'Event not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'An error occurred: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetUserQRInfoAPIView(APIView):
    """
    Get user's QR code information for display in membership card
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        return Response({
            'user_info': {
                'user_id': str(user.user_id),
                'username': user.username,
                'email': user.email,
                'phone_number': user.phone_number,
                'company_name': user.company_name,
                'designation': user.designation,
                'user_type': user.user_type,
                'membership_expiry': user.membership_expiry,
                'is_active': user.is_active,
                'profile_picture': user.profile_picture.url if user.profile_picture else None
            },
            'qr_code_url': user.qr_code.url if user.qr_code else None,
            'membership_card_url': user.membership_card_url if user.membership_card_url else None
        }, status=status.HTTP_200_OK)



