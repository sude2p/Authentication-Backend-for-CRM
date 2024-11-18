from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from .manager import CustomUserManger
from django.apps import apps
import pyotp
import uuid

from .utils import UserType

# Create your models here.


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model that extends AbstractBaseUser and PermissionsMixin for authentication and permissions.

    Fields:
        email (EmailField): Unique email address used as the username for authentication.
        first_name (CharField): Optional first name of the user.
        last_name (CharField): Optional last name of the user.
        is_staff (BooleanField): Indicates if the user has staff privileges. Defaults to False.
        is_admin (BooleanField): Indicates if the user has admin privileges. Defaults to False.
        otp_secret (CharField): Optional secret key for generating OTP codes, defaulting to a random base32 string.

    Manager:
        objects: Instance of CustomUserManager for handling user creation.

    Meta:
        USERNAME_FIELD: Specifies 'email' as the field used for user authentication.
        REQUIRED_FIELDS: List of required fields besides email. Defaults to an empty list.

    Methods:
        __str__(): Returns a string representation of the user as 'email (first_name)'.
    """
    email = models.EmailField(verbose_name="Email",
                              max_length=255,
                              unique=True)
    first_name = models.CharField(max_length=200, null=True, blank=True)
    last_name = models.CharField(max_length=200, null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=32, default=pyotp.random_base32, blank=True, null=True)
     
    objects = CustomUserManger()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return f' {self.email} ({self.first_name})'
        
    
    @property
    def full_name(self):
        return f"{self.first_name.strip()} {self.last_name}"
        
    
    def has_perm(self, perm, obj=None ):
        if self.is_admin:
            return True
        has_permission = super().has_perm(perm, obj)
        # print(f"checking permission {perm} for user {self.email}:{has_permission}")
        return has_permission
    
    def has_module_perms(self, app_label: str):
        if self.is_admin:
            return True
        
        has_permission = super().has_module_perms(app_label)
        # print(f"Checking module permissions for {app_label} for user {self.email}: {has_permission}")
        return has_permission
    
class UserProfile(models.Model):
    """
    UserProfile model that extends the User model with additional fields.

    Fields:
        user (User): One-to-one relationship with the User model.
        contact_number (str): Unique contact number for the user (optional).
        is_active (bool): Indicates if the user profile is active.
        is_verified (bool): Indicates if the user profile is verified.
        user_type (str): Type of user (Admin or Org User).
        created_by (UserProfile): Admin user who created this profile.
        organization (Organization): Organization the user is associated with.
        created_at (datetime): Timestamp when the profile was created.
        updated_at (datetime): Timestamp when the profile was last updated.

    Methods:
        __str__: Returns a string representation of the user profile, including the user and user type.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE ,primary_key=True,related_name='userprofile') 
    contact_number = models.CharField(max_length=10, blank=True, null=True, unique=False)
    is_active = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    user_type = models.CharField(max_length=20, choices=[(tag.name, tag.value) for tag in UserType],
                                 default=UserType.USER.name)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)
    # to avoid circular imports
    organization = models.ForeignKey(
        'organization.Organization', 
        on_delete=models.SET_NULL, 
        null=True
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user}-{self.user_type}"
    
    
    def delete(self, *args, **kwargs):
        # First, delete the associated User object
        self.user.delete()
        # Then, call the superclass delete method to delete the UserProfile
        super().delete(*args, **kwargs)
    
    
    
        
    
    
