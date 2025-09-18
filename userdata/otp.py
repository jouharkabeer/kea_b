import requests
from .models import CustomUser
import json
import logging
import random

# Configure logging
logger = logging.getLogger(__name__)

# API credentials for MessageCentral
token = 'eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJDLTdFNEQyNEQzRTJGMjRCOSIsImlhdCI6MTc1MDI2NTc4OSwiZXhwIjoxOTA3OTQ1Nzg5fQ.bj8MA-IIAN6gV08HLKRT3w7Tor7m4oR8F4M9CQhggGOSsRU4R5fDSohNBnC8RWaiOOPAMlPOg63czjHRtNhfNg'
c_id = 'C-7E4D24D3E2F24B9'

def send_otp(number):
    """
    Send OTP to the given phone number.
    
    In case of API issues, generates a local OTP instead.
    """
    # Validate phone number format
    cleaned_number = clean_phone_number(number)
    if not cleaned_number:
        return {"error": "Invalid phone number format. Please enter a 10-digit number."}

    # Log the request
    logger.info(f"Sending OTP to: {cleaned_number}")
    
    # Try to send with API first
    api_result = _send_otp_via_api(cleaned_number)
    
    # If API fails, generate a local OTP
    if "error" in api_result:
        logger.warning(f"API OTP failed: {api_result['error']}. Generating local OTP.")
        return generate_local_otp(cleaned_number)
    
    return api_result


def _send_otp_via_api(number):
    """Internal function to send OTP via MessageCentral API"""
    # Create the API request with proper formatting
    url = "https://cpaas.messagecentral.com/verification/v3/send"
    
    # Use query parameters for API request
    params = {
        "countryCode": "91",
        "customerId": c_id,
        "flowType": "SMS",
        "mobileNumber": number
    }
    
    headers = {
        'authToken': token,
        'Content-Type': 'application/json'
    }

    try:
        # Make the API request and log details
        logger.info(f"OTP API Request: {url} - Params: {params}")
        response = requests.request("POST", url, headers=headers, params=params)
        
        # Log the response
        logger.info(f"OTP API Response: Status {response.status_code} - Body: {response.text}")
        
        if response.status_code == 200:
            try:
                response_json = response.json()
                
                # Check if the API returned an error status
                if response_json.get('responseCode') != 200:
                    error_msg = response_json.get('responseMessage', 'Unknown API error')
                    return {"error": f"API error: {error_msg}"}
                
                # Get verification ID
                verification_id = response_json.get('data', {}).get('verificationId')
                if not verification_id:
                    return {"error": "Missing verification ID in response"}
                
                # If user exists, update their OTP field
                try:
                    user = CustomUser.objects.get(phone_number=number)
                    user.otp = verification_id
                    user.save()
                except CustomUser.DoesNotExist:
                    # User doesn't exist, which is fine for registration flow
                    pass
                    
                # Return verification_id for registration flow
                return {
                    "message": "OTP sent successfully!",
                    "verification_id": verification_id
                }
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                logger.error(f"Error parsing OTP response: {str(e)}")
                return {"error": f"Failed to parse OTP response: {str(e)}", "raw_response": response.text}
        else:
            logger.error(f"OTP API error: {response.status_code} - {response.text}")
            return {"error": f"Failed to send OTP. Status code: {response.status_code}", "details": response.text}
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error sending OTP: {str(e)}")
        return {"error": f"Network error sending OTP: {str(e)}"}


def generate_local_otp(number):
    """Generate a local OTP when API fails"""
    # Generate a 6-digit OTP
    otp = str(random.randint(100000, 999999))
    
    try:
        # If user exists, update their OTP field
        user = CustomUser.objects.get(phone_number=number)
        user.otp = otp
        user.save()
    except CustomUser.DoesNotExist:
        # User doesn't exist, which is fine for registration
        pass
    
    # Return the OTP as verification_id
    return {
        "message": "OTP generated successfully! (Note: Using local OTP generation)",
        "verification_id": otp,
        "test_otp": otp  # Include actual OTP for testing
    }


def verify_otp(number, otp, verification_id=None):
    """
    Verify the OTP.
    Supports both API verification and local verification.
    """
    # Validate phone number
    cleaned_number = clean_phone_number(number)
    if not cleaned_number:
        return {"error": "Invalid phone number format. Please enter a 10-digit number."}

    # If verification_id is not provided, try to get it from user record
    if verification_id is None:
        try:
            user = CustomUser.objects.get(phone_number=cleaned_number)
            verification_id = user.otp
            if not verification_id:
                return {"error": "No OTP was sent for this number"}
        except CustomUser.DoesNotExist:
            return {"error": "No user found with this number"}

    # Log the verification attempt
    logger.info(f"Verifying OTP for number: {cleaned_number}, verification_id: {verification_id}")
    
    # First try direct verification (handles local OTPs)
    if verification_id == otp:
        # OTP matches verification_id directly
        _mark_user_verified(cleaned_number)
        return {"message": "OTP verified successfully"}
    
    # If direct match failed, try API verification
    api_result = _verify_otp_via_api(cleaned_number, otp, verification_id)
    
    if "error" not in api_result:
        # API verification succeeded
        _mark_user_verified(cleaned_number)
        
    return api_result


def _verify_otp_via_api(number, otp, verification_id):
    """Internal function to verify OTP via MessageCentral API"""
    # Create the API request
    url = "https://cpaas.messagecentral.com/verification/v3/validateOtp"
    
    params = {
        "countryCode": "91",
        "mobileNumber": number,
        "verificationId": verification_id,
        "customerId": c_id,
        "code": otp
    }
    
    headers = {
        'authToken': token,
        'Content-Type': 'application/json'
    }

    try:
        # Make the API request
        logger.info(f"OTP Verify Request: {url} - Params: {params}")
        response = requests.request("GET", url, headers=headers, params=params)
        
        # Log the response
        logger.info(f"OTP Verify Response: Status {response.status_code} - Body: {response.text}")
        
        if response.status_code == 200:
            try:
                response_json = response.json()
                if response_json.get('responseCode') == 200:
                    return {"message": "OTP verified successfully"}
                else:
                    error_msg = response_json.get('responseMessage', 'Invalid OTP')
                    return {"error": error_msg}
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                logger.error(f"Error parsing OTP verification response: {str(e)}")
                return {"error": f"Unexpected response format: {str(e)}", "raw_response": response.text}
        else:
            logger.error(f"OTP verification API error: {response.status_code} - {response.text}")
            return {"error": f"OTP verification failed. Status code: {response.status_code}", "details": response.text}
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error verifying OTP: {str(e)}")
        return {"error": f"Network error verifying OTP: {str(e)}"}


def _mark_user_verified(number):
    """Mark a user as verified after successful OTP verification"""
    try:
        user = CustomUser.objects.get(phone_number=number)
        user.is_verified = True
        user.otp = None  # Clear OTP after successful verification
        user.save()
        logger.info(f"User with phone {number} marked as verified")
    except CustomUser.DoesNotExist:
        # This is fine for registration flow
        logger.info(f"No existing user found with phone {number} during verification")
        pass


def clean_phone_number(number):
    """Clean and validate the phone number format"""
    if not number:
        return None
        
    # Remove any non-digit characters
    clean_num = ''.join(filter(str.isdigit, str(number)))
    
    # Remove country code if present
    if clean_num.startswith('91') and len(clean_num) > 10:
        clean_num = clean_num[2:]
    
    # Ensure it's a 10-digit number
    if len(clean_num) != 10:
        return None
        
    return clean_num
