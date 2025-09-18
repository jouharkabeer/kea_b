from django.db import models
from django.contrib.auth import get_user_model
import uuid
CustomUser = get_user_model()


class Event(models.Model):
    event_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, related_name="events")
    event_name = models.CharField(max_length=100)  
    event_sub_name = models.CharField(max_length=30)
    description = models.TextField() 
    location = models.CharField(max_length=255) 
    fee_for_member = models.DecimalField(max_digits=10, decimal_places=2) 
    fee_for_external = models.DecimalField(max_digits=10, decimal_places=2)  
    registration_ends = models.DateTimeField()
    event_time = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.event_name} - {self.event_sub_name}"
    

class EventRegistration(models.Model):
    event_registration_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    registered_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    registered_on = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    fee_paid = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    checked_in = models.BooleanField(default=False)
    checked_in_at = models.DateTimeField(null=True, blank=True)
    checked_in_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='checked_in_registrations') 
