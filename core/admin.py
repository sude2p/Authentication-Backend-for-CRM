from django.contrib import admin
from core.models import User, UserProfile
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from organization.models import Organization

class UserModelAdmin(BaseUserAdmin):
    """
    Admin interface customization for the User model.

    Customizations:
        - list_display: Shows selected User and UserProfile fields in the list view.
        - list_filter: Filters users based on UserProfile attributes.
        - get_queryset: Optimizes queryset by selecting related UserProfile.
        - fieldsets/add_fieldsets: Organizes fields for viewing and creating users.
    """
    # Display user attributes
    list_display = [
        "id", "email", "get_first_name", "is_admin","is_staff", "get_last_name", "get_contact_number", 
        "get_is_active", "get_is_verified", "get_user_type"
    ]
    list_filter = ["userprofile__is_active", "userprofile__is_verified", "userprofile__user_type"]

    def get_first_name(self, obj):
        return obj.first_name
    get_first_name.short_description = 'First Name'
    
    def get_last_name(self, obj):
        return obj.last_name
    get_last_name.short_description = 'Last Name'
    
    def get_contact_number(self, obj):
        return obj.userprofile.contact_number if obj.userprofile else None
    get_contact_number.short_description = 'Contact Number'
    
    def get_is_active(self, obj):
        return obj.userprofile.is_active if obj.userprofile else None
    get_is_active.short_description = 'Active'
    
    def get_is_verified(self, obj):
        return obj.userprofile.is_verified if obj.userprofile else None
    get_is_verified.short_description = 'Verified'
    
    def get_user_type(self, obj):
        return obj.userprofile.user_type if obj.userprofile else None
    get_user_type.short_description = 'User Type'
    
    # Define fieldsets
    fieldsets = [
        ('User Credentials', {"fields": ["email", "password","is_admin", "is_staff",]}),
        ("Personal Info", {"fields": ["first_name", "last_name"]}),
        ("Permissions", {"fields": ["groups", "user_permissions"]}),
    ]
    
    add_fieldsets = [
        (
            None,
            {
                "classes": ["wide"],
                "fields": ["email", "first_name", "last_name", "contact_number", "password1", "password2"],
            },
        ),
    ]
    
    search_fields = ["email"]
    ordering = ["id", "email"]
    filter_horizontal = ['groups', 'user_permissions']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('userprofile')

class UserProfileAdmin(admin.ModelAdmin):
    """
    Admin interface configuration for UserProfile model.

    - Displays: user, contact_number, is_active, is_verified, user_type, created_by, and organization.
    - Filters: is_active, is_verified, user_type, created_by.
    - Fieldsets: User Profile Info section with fields: user, contact_number, is_active, is_verified, user_type, created_by.
    - Excludes: created_at, updated_at from the form.
    - Search: user email and contact_number.
    - Ordering: user.
    """
    # Display profile attributes
    list_display = [
       "user", "contact_number", "is_active", "is_verified", "user_type", "created_by","organization",
    ]
    
    
    list_filter = ["is_active", "is_verified", "user_type", "created_by"]

    # Define fieldsets
    fieldsets = [
        ('User Profile Info', {"fields": ["user", "contact_number", "is_active", "is_verified", "user_type", "created_by","organization"]}),
    ]
    
    # Exclude non-editable fields from the form
    exclude = ['created_at', 'updated_at']
    
    search_fields = ["user__email", "contact_number"]
    ordering = ["user"]
    
    # Exclude non-editable fields from the form
    exclude = ['created_at', 'updated_at']
    
    search_fields = ["user__email", "contact_number"]
    ordering = ["user"]

# Register the admin models
admin.site.register(User, UserModelAdmin)

admin.site.register(UserProfile, UserProfileAdmin)

