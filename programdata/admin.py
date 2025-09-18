# admin.py for Event and EventRegistration models

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import Event, EventRegistration

class EventRegistrationInline(admin.TabularInline):
    model = EventRegistration
    extra = 0
    readonly_fields = ('event_registration_id', 'registered_on', 'fee_paid')
    fields = ('registered_by', 'fee_paid', 'is_active', 'registered_on')
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def get_queryset(self, request):
        # Optimize queryset with select_related to reduce DB queries
        qs = super().get_queryset(request)
        return qs.select_related('registered_by')

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('event_name', 'event_sub_name', 'location', 'event_date', 
                   'event_time_display', 'registration_status', 'fees_display', 
                   'registrations_count', 'is_active')
    list_filter = ('is_active', 'event_time', 'created_at')
    search_fields = ('event_name', 'event_sub_name', 'description', 'location')
    readonly_fields = ('event_id', 'created_at', 'registrations_count_detail')
    
    fieldsets = (
        ('Event Details', {
            'fields': ('event_id', 'event_name', 'event_sub_name', 'description', 'location')
        }),
        ('Timing', {
            'fields': ('event_time', 'registration_ends')
        }),
        ('Fees', {
            'fields': ('fee_for_member', 'fee_for_external')
        }),
        ('Status', {
            'fields': ('is_active', 'created_by', 'created_at', 'registrations_count_detail')
        }),
    )
    
    inlines = [EventRegistrationInline]
    
    def event_date(self, obj):
        return obj.event_time.strftime('%d %b %Y')
    event_date.short_description = 'Date'
    
    def event_time_display(self, obj):
        return obj.event_time.strftime('%I:%M %p')
    event_time_display.short_description = 'Time'
    
    def registration_status(self, obj):
        now = timezone.now()
        if obj.registration_ends < now:
            return format_html('<span style="color:red">Closed</span>')
        elif (obj.registration_ends - now).days <= 2:
            return format_html('<span style="color:orange">Closing Soon</span>')
        else:
            return format_html('<span style="color:green">Open</span>')
    registration_status.short_description = 'Registration'
    
    def fees_display(self, obj):
        return format_html(
            'Members: <b>₹{}</b><br>External: <b>₹{}</b>',
            obj.fee_for_member, obj.fee_for_external
        )
    fees_display.short_description = 'Fees'
    
    def registrations_count(self, obj):
        count = obj.eventregistration_set.count()
        return count
    registrations_count.short_description = 'Registrations'
    
    def registrations_count_detail(self, obj):
        total = obj.eventregistration_set.count()
        active = obj.eventregistration_set.filter(is_active=True).count()
        return format_html(
            '<div style="margin-top:5px;">'
            '<span style="font-weight:bold;">Total Registrations:</span> {}<br>'
            '<span style="font-weight:bold;">Active Registrations:</span> {}'
            '</div>',
            total, active
        )
    registrations_count_detail.short_description = 'Registration Stats'
    
    actions = ['activate_events', 'deactivate_events', 'close_registrations']
    
    def activate_events(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} events have been activated.")
    activate_events.short_description = "Activate selected events"
    
    def deactivate_events(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} events have been deactivated.")
    deactivate_events.short_description = "Deactivate selected events"
    
    def close_registrations(self, request, queryset):
        queryset.update(registration_ends=timezone.now())
        self.message_user(request, f"Registration closed for {queryset.count()} events.")
    close_registrations.short_description = "Close registration for selected events"
    
    def save_model(self, request, obj, form, change):
        if not change:  # If creating a new object
            obj.created_by = request.user
        super().save_model(request, obj, form, change)

@admin.register(EventRegistration)
class EventRegistrationAdmin(admin.ModelAdmin):
    list_display = ('display_id', 'event_name', 'registered_by_name', 'registered_on', 'fee_paid', 'is_active')
    list_filter = ('is_active', 'registered_on', 'event__event_name')
    search_fields = ('registered_by__username', 'registered_by__email', 'event__event_name')
    readonly_fields = ('event_registration_id', 'registered_on', 'payment_details')
    
    fieldsets = (
        ('Registration Details', {
            'fields': ('event_registration_id', 'event', 'registered_by', 'registered_on')
        }),
        ('Status', {
            'fields': ('is_active', 'fee_paid', 'payment_details')
        }),
    )
    
    def display_id(self, obj):
        return str(obj.event_registration_id)[:8] + '...'  # Show shortened UUID
    display_id.short_description = 'Registration ID'
    
    def event_name(self, obj):
        url_name = f"admin:{obj.event._meta.app_label}_{obj.event._meta.model_name}_change"
        try:
            url = reverse(url_name, args=[obj.event.pk])
            return format_html('<a href="{}">{} - {}</a>', 
                              url, obj.event.event_name, obj.event.event_sub_name)
        except:
            return f"{obj.event.event_name} - {obj.event.event_sub_name}"
    event_name.short_description = 'Event'
    
    def registered_by_name(self, obj):
        app_label = obj.registered_by._meta.app_label
        model_name = obj.registered_by._meta.model_name
        url_name = f"admin:{app_label}_{model_name}_change"
        
        try:
            url = reverse(url_name, args=[obj.registered_by.pk])
            return format_html('<a href="{}">{}</a>', url, obj.registered_by.username)
        except:
            return obj.registered_by.username
    registered_by_name.short_description = 'Registered By'
    
    def payment_details(self, obj):
        if not obj.fee_paid:
            return "No payment recorded"
        
        if hasattr(obj, 'registered_by') and hasattr(obj.registered_by, 'payment_set'):
            # Find related payments - this assumes a Payment model exists
            try:
                payments = obj.registered_by.payment_set.filter(
                    created_at__lte=obj.registered_on + timezone.timedelta(minutes=10),
                    created_at__gte=obj.registered_on - timezone.timedelta(minutes=10)
                )
                if payments.exists():
                    payment = payments.first()
                    return format_html(
                        'Payment ID: <code>{}</code><br>'
                        'Amount: <b>₹{}</b><br>'
                        'Status: <b>{}</b>',
                        payment.payment_id or "N/A",
                        payment.amount,
                        payment.status
                    )
            except:
                pass
                
        return format_html('Amount Paid: <b>₹{}</b>', obj.fee_paid)
    
    payment_details.short_description = 'Payment Information'
    
    actions = ['activate_registrations', 'deactivate_registrations']
    
    def activate_registrations(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} registrations have been activated.")
    activate_registrations.short_description = "Activate selected registrations"
    
    def deactivate_registrations(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} registrations have been deactivated.")
    deactivate_registrations.short_description = "Deactivate selected registrations"
    
    # Optimize querysets to reduce database queries
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('event', 'registered_by')