from django.contrib.auth.models import BaseUserManager
from .utils import  UserType
from django.apps import apps

class CustomUserManger(BaseUserManager):
    """
    Manager for User model with methods to create regular and superusers.

    Methods:
        create_user: Creates and returns a regular user with the given email, password, and optional user type.
        create_superuser: Creates and returns a superuser with the given email and password.
    """
    #create a normal user
    def create_user(self, email, password=None, user_type=None, created_by=None ,**extra_fields):
        """
    Creates and saves a new user with the given email, password, user type, and additional fields.

    Args:
        email (str): The email address of the user (required).
        password (str, optional): The password for the user. Defaults to None.
        user_type (str, optional): The type of user (if applicable). Defaults to None.
        created_by (any, optional): The creator of the user (if applicable). Defaults to None.
        **extra_fields: Additional fields to set on the user object.

    Raises:
        ValueError: If the email is not provided.

    Returns:
        user: The newly created user instance.
    """
        if not email:
            raise ValueError('User must have an email address')
        user = self.model(email=email, **extra_fields) # create a new user instance
        user.set_password(password)
        user.save(using=self._db) 
        return user
    
        
    def create_superuser(self, email, password=None, **extra_fields):
        #create a superuser
        """
    Creates and saves a superuser with the given email, password, and additional fields.

    Args:
        email (str): The email address of the superuser (required).
        password (str, optional): The password for the superuser. Defaults to None.
        **extra_fields: Additional fields to set on the superuser object.

    Sets the following default fields for a superuser:
        - is_superuser: True
        - is_staff: True
        - is_admin: True
        - user_type: 'ADMIN'

    Returns:
        user: The newly created superuser instance.
    """
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('user_type', UserType.ADMIN.name)
        user = self.create_user(email=email, password=password, **extra_fields)
        return user
    
   