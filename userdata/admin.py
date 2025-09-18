# Fixed admin.py

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import CustomUser, Payment, OTPVerification

class PaymentInline(admin.TabularInline):
    model = Payment
    extra = 0
    readonly_fields = ('order_id', 'payment_id', 'signature', 'status', 'created_at', 'updated_at')
    can_delete = False
    
    def has_add_permission(self, request, obj=None):
        return False
    
    fields = ('amount', 'status', 'order_id', 'payment_id', 'created_at')

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'phone_number', 'user_type', 'membership_status', 'membership_expiry_date', 'is_verified', 'view_card')
    list_filter = ('user_type', 'is_active', 'is_verified', 'is_staff')
    search_fields = ('username', 'email', 'phone_number', 'user_id')
    readonly_fields = ('user_id', 'membership_card_preview', 'qr_code_preview')
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('user_id', 'username', 'email', 'phone_number', 'password')
        }),
        ('Personal Details', {
            'fields': ('company_name', 'designation', 'address', 'profile_picture')
        }),
        ('Education Details', {
            'fields': ('department_of_study', 'year_of_graduation')
        }),
        ('Membership', {
            'fields': ('user_type', 'is_active', 'membership_expiry', 'membership_card', 'membership_card_url', 'membership_card_preview', 'qr_code', 'qr_code_preview')
        }),
        ('Verification', {
            'fields': ('is_verified', 'otp', 'otp_tries', 'otp_expiry')
        }),
        ('Permissions', {
            'fields': ('is_staff', 'is_superuser', 'groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
    )
    
    inlines = [PaymentInline]
    
    def membership_status(self, obj):
        if not obj.is_active:
            return format_html('<span style="color:red">Inactive</span>')
        
        if not obj.membership_expiry:
            return format_html('<span style="color:orange">Pending</span>')
            
        if obj.membership_expiry > timezone.now():
            days_left = (obj.membership_expiry - timezone.now()).days
            return format_html('<span style="color:green">Active ({} days left)</span>', days_left)
        else:
            return format_html('<span style="color:red">Expired</span>')
    
    membership_status.short_description = 'Status'
    
    def membership_expiry_date(self, obj):
        if not obj.membership_expiry:
            return '-'
        return obj.membership_expiry.strftime('%d %b %Y')
    
    membership_expiry_date.short_description = 'Expires On'
    
    def view_card(self, obj):
        if obj.membership_card_url:
            return format_html('<a href="{}" target="_blank">View Card</a>', obj.membership_card_url)
        return '-'
    
    view_card.short_description = 'Card'
    
    def membership_card_preview(self, obj):
        if obj.membership_card:
            return format_html('<a href="{}" target="_blank"><img src="{}" width="300" /></a>', 
                              obj.membership_card.url, obj.membership_card.url)
        return "No card uploaded"
    
    membership_card_preview.short_description = 'Membership Card Preview'
    
    def qr_code_preview(self, obj):
        if obj.qr_code:
            return format_html('<img src="{}" width="150" />', obj.qr_code.url)
        return "No QR code generated"
    
    qr_code_preview.short_description = 'QR Code Preview'
    
    actions = ['activate_membership', 'deactivate_membership', 'generate_card']
    
    def activate_membership(self, request, queryset):
        for user in queryset:
            user.activate_membership()
        self.message_user(request, f"{queryset.count()} users have had their memberships activated for 1 year.")
    
    activate_membership.short_description = "Activate membership for selected users"
    
    def deactivate_membership(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} users have had their memberships deactivated.")
    
    deactivate_membership.short_description = "Deactivate membership for selected users"
    
    def generate_card(self, request, queryset):
        # This would integrate with your card generation logic
        self.message_user(request, "Card generation requested for selected users.")
    
    generate_card.short_description = "Generate membership cards for selected users"

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ('user_display', 'amount', 'status', 'payment_id', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('user__username', 'user__email', 'order_id', 'payment_id')
    readonly_fields = ('created_at', 'updated_at')
    
    def user_display(self, obj):
        # Fixed: Get the correct admin URL based on your actual app name
        app_label = obj.user._meta.app_label
        model_name = obj.user._meta.model_name
        
        # Generate the correct URL pattern name
        url_name = f"admin:{app_label}_{model_name}_change"
        
        try:
            # Generate the URL
            url = reverse(url_name, args=[obj.user.pk])
            return format_html('<a href="{}">{}</a>', url, obj.user.username)
        except:
            # Fallback if URL resolution fails
            return obj.user.username
    
    user_display.short_description = 'User'

@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ('phone_number', 'otp', 'verified', 'otp_tries', 'otp_expiry')
    list_filter = ('verified',)
    search_fields = ('phone_number',)
    readonly_fields = ('otp_expiry',)