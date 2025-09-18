from django.urls import path
from .views import *
urlpatterns = [

    path('register/', RegisterUserView.as_view(), name='register'),
    path('check-user-exists/', CheckUserExistsView.as_view(), name='check-user-exists'),
    path('delete-user/', DeleteUserView.as_view(), name='delete-user'),
    path('create-razorpay-order/', CreateRazorpayOrderView.as_view(), name='create_razorpay_order'),
    path('verify-payment/', VerifyPaymentView.as_view(), name='verify_payment'),

    path('payments/test/', TestPaymentView.as_view(), name='test_payment'),
    path('login/password/', PasswordLoginView.as_view(), name='login-password'),
    path('userdetail/', Userdetails.as_view(), name="all member detail" ),
    path('allusers/', AllUserdetails.as_view(), name="all user detail" ),
    path('user/', Userdetails.as_view(), name='user-details'),


    path('user/profile/', UserProfileView.as_view(), name='user-profile'),
    # path('user/profile/me/', get_user_profile, name='get-user-profile'),  
    path('user/profile/change-password/', change_password, name='change-password'),
    path('user/profile/delete-picture/', delete_profile_picture, name='delete-profile-picture'),



    path('activate/', ActivateMemberView.as_view(), name='activate-member'),
    path('otpverify/', VerifyOTPView.as_view(), name='verify_otp'),
    path('send-otp/',SendOTPView.as_view(), name='send_otp'),
    path('allmembers/', AllMemberdetails.as_view(), name="all member detail" ),



    path('generate-qr-code/', GenerateQRCodeView.as_view(), name='generate-qr-code'),
    path('generate-membership-card/', GenerateMembershipCardView.as_view(), name='generate-membership-card'),
    path('download-membership-card/<str:user_id>/', DownloadMembershipCardView.as_view(), name='download-membership-card'),
    path('send-membership-card-email/', SendMembershipCardEmailView.as_view(), name='send-membership-card-email'),
    path('preview-membership-card/<str:user_id>/', MembershipCardPreviewView.as_view(), name='preview-membership-card'),
    path('view-card/<str:user_id>/', DirectPDFView.as_view(), name='view-card'),
    path('regenerate-membership-card/',  RegenerateMembershipCardAPIView.as_view(), name='regenerate-membership-card-api'),


    path('password-reset/', RequestPasswordResetView.as_view(), name='password-reset-request'),
    path('password-reset/validate/', ValidateTokenView.as_view(), name='password-reset-validate'),
    path('password-reset/confirm/', ResetPasswordView.as_view(), name='password-reset-confirm'),
    
    
]
