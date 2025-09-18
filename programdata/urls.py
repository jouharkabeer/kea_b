from django.urls import path
from .views import *



event_registration_list = EventRegistrationViewSet.as_view({
    'get': 'list',
    'post': 'create'
})

event_registration_detail = EventRegistrationViewSet.as_view({
    'get': 'retrieve',
    'put': 'update',
    'patch': 'partial_update',
    'delete': 'destroy'
})


urlpatterns = [
    
    path('events/', Eventview.as_view(), name='event'),
    path('event/create/', EventCreate.as_view(), name='event create'), 
    path('event/update/<uuid:testimonial_id>/', EventUpdate.as_view(), name='event update'),
    path('event/delete/<uuid:testimonial_id>/', EventDelete.as_view(), name='event delete'),




    path('event-registrations/', event_registration_list, name='event-registration-list'),
    path('event-registrations/<uuid:pk>/', event_registration_detail, name='event-registration-detail'),
    path('create-razorpay-order/', RazorpayOrderAPIView.as_view(), name='create-razorpay-order'),
    path('check-registration/', CheckRegistrationAPIView.as_view(), name='check-registration'),
    path('verify-user-event-registration/', VerifyUserEventRegistrationAPIView.as_view(), name='verify-user-event-registration'),



    path('scan-qr-event-checkin/', ScanQRForEventCheckInAPIView.as_view(), name='scan-qr-event-checkin'),
    path('confirm-event-checkin/', ConfirmEventCheckInAPIView.as_view(), name='confirm-event-checkin'),
    path('event-attendance/<uuid:event_id>/', EventAttendanceListAPIView.as_view(), name='event-attendance'),
    path('get-user-qr-info/', GetUserQRInfoAPIView.as_view(), name='get-user-qr-info'),
]

