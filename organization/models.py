from django.db import models
from django.contrib.auth import get_user_model
from django.conf import settings
from core.models import User

# Create your models here.


class Organization(models.Model):
    """
    Represents an organization with various attributes detailing its profile.

    Attributes:
        name (CharField): The name of the organization.
        industry (CharField): The industry in which the organization operates.
        description (TextField): A brief description of the organization.
        address (CharField): The complete address of the organization (optional).
        street (CharField): The street name of the organization's location.
        postal_code (CharField): The postal code of the organization's location.
        city (CharField): The city where the organization is located.
        province (CharField): The province or state of the organization's location (optional).
        country (CharField): The country where the organization is based.
        website (URLField): The official website of the organization (optional).
        email (EmailField): The official email address of the organization; must be unique.
        logo (ImageField): The logo of the organization; stored in the 'organization_logos/' directory (optional).
        contact_number (CharField): The primary contact number for the organization.
        organization_type (CharField): The type or classification of the organization (optional).
        kyc_verified (BooleanField): Indicates whether the organization has completed KYC (Know Your Customer) verification; defaults to False.
        established_date (DateField): The date when the organization was established (optional).
        created_by (ForeignKey): A reference to the user who created this organization; links to the user model.
        created_at (DateTimeField): The timestamp when the organization record was created; auto-populated.
        updated_at (DateTimeField): The timestamp when the organization record was last updated; auto-populated.

    Methods:
        __str__(): Returns a string representation of the organization, including its name and the creator's identifier.
    """
    
    name = models.CharField(max_length=200)
    industry = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    street = models.CharField(max_length=255)
    postal_code = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    province = models.CharField(max_length=200, blank=True)
    country = models.CharField(max_length=200)
    website = models.URLField(max_length=200, null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True)
    logo = models.ImageField(upload_to='organization_logos/', null=True, blank=True)
    contact_number = models.CharField(max_length=13)
    organization_type = models.CharField(max_length=200, blank=True)
    kyc_verified = models.BooleanField(default=False)
    established_date = models.DateField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='created_organizations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f'{self.name}-{self.created_by}'
