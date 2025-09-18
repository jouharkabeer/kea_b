from rest_framework import serializers
from .models import *


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = '__all__'



class EventRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventRegistration
        fields = '__all__'
        read_only_fields = ('event_registration_id', 'registered_on', 'registered_by', 'fee_paid')

    def validate(self, attrs):
        user = self.context['request'].user
        event = attrs['event']

        if EventRegistration.objects.filter(event=event, registered_by=user).exists():
            raise serializers.ValidationError("You have already registered for this event.")

        return attrs

    def create(self, validated_data):
        user = self.context['request'].user
        event = validated_data['event']

        fee = event.fee_for_member if user.is_active else event.fee_for_external

        validated_data['fee_paid'] = fee
        validated_data['registered_by'] = user

        return super().create(validated_data)