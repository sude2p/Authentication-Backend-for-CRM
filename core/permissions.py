from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import User, UserProfile
from organization.models import Organization

class IsAdminOrSelf(BasePermission):
    """
    Custom permission to allow admin users to create and update profiles and non-admin users to view their own profile.

    Admin users have permission to create and update profiles but cannot delete them. Non-admin users can only 
    view (GET) their own profile and cannot perform other operations.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.method in SAFE_METHODS or (request.user.is_admin and request.method in ['POST', 'PUT','PATCH']):
            return True

        # Non-admin users can only GET their own profile
        if request.user and request.user.is_authenticated and request.method in SAFE_METHODS:
            return True
        
        return False

    def has_object_permission(self, request, view, obj):
        # Admin users can do everything except delete
        if request.user.is_admin and request.method in ['POST', 'PUT','PATCH']:
            return True    
           
        # Non-admin users can only view their own profile
        if request.method in SAFE_METHODS and obj.id == request.user.id:
            return True
        
        return False
    
class IsAdminUserAndOwner(BasePermission):
    """
    Custom permission class to grant access based on admin status and ownership of the object.

    Permissions:
        - `has_permission`: Grants access to admin users who are authenticated.
        - `has_object_permission`: Grants object-level access based on the following:
            - Admin users can access objects created by themselves or within their organization.
            - Non-admin users can only access objects they have created.

    Methods:
        has_permission(request, view):
            - Returns True if the user is authenticated and an admin.
            - For non-admins, additional checks can be added.

        has_object_permission(request, view, obj):
            - Admins can access objects created by themselves or within their organization.
            - Non-admins can only access their own created objects.
    """
    def has_permission(self, request, view):
            # Allow admin users to access the view
            if request.user.is_authenticated and request.user.is_admin:
                return True
            
            # Additional checks for non-admin users, if needed
            return False

    def has_object_permission(self, request, view, obj):
        # For admin users, we might want to restrict access to their own data
        if request.user.is_admin:
            # Restrict access to objects created by the admin user
           
             return (obj.userprofile.organization.created_by == request.user or obj.userprofile.created_by == request.user)
        # Non-admin users can only access their own records
        return obj.userprofile.created_by == request.user    
    

class IsOrganizationMember(BasePermission):
    """
    Custom permission class to check if the user is a member of the specified organization.

    Permissions:
        - `has_permission`: Grants access based on the user's role and organization membership.
            - Admin users: Access is granted if they created the specified organization.
            - Staff users: Access is granted if they belong to the specified organization.

    Methods:
        has_permission(request, view):
            - For admin users:
                - Checks if the organization specified in the request header ('Organization') exists and was created by the user.
            - For staff users:
                - Checks if the user is a member of the organization specified in the request header ('Organization').

    Returns:
        True if the user is authorized, otherwise False.
    """
    def has_permission(self, request, view):
        if request.user.is_admin and request.user.is_authenticated:
            organization_id = request.headers.get('Organization')
            try:
                Organization.objects.get(id=organization_id, created_by=request.user)
                
            except Organization.DoesNotExist:
                return False
            return True
        
        elif request.user.is_staff and request.user.is_authenticated:
            organization_id = request.headers.get('Organization')
            
            try:
                UserProfile.objects.get(user=request.user, organization_id=organization_id)
            except UserProfile.DoesNotExist:
                return False
            return True    
        
          