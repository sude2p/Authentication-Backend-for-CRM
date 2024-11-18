from django.contrib import admin
from organization.models import Organization

# Register your models here.
class OrganizationAdmin(admin.ModelAdmin):
    """
    Admin interface configuration for the Organization model.

    - Displays: id, name, address, email, contact_number, organization_type, created_by, created_at, updated_at.
    - Searchable fields: name, address, email, contact_number.
    - Filters: created_by, created_at, organization_type.
    - Ordering: by created_at in descending order.
    - Read-only fields: created_at, updated_at.
    """
    list_display = ('id','name', 'address', 'email', 'contact_number', 'organization_type', 'created_by', 'created_at', 'updated_at')
    search_fields = ('name', 'address', 'email', 'contact_number')
    list_filter = ('created_by', 'created_at', 'organization_type')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at') 
    
admin.site.register(Organization, OrganizationAdmin)