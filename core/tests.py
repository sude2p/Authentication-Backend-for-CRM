from rest_framework import status
from rest_framework.test import APITestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from .models import UserProfile
from django.core import mail
User = get_user_model()

class AdminUserTests(APITestCase):
    def setUp(self):
        """
        Set up data for testing.
        """
        # Create an initial admin user
        self.admin_user = User.objects.create_superuser(
            email="admin@example.com",
            password="Admin12345",
            first_name="Admin",
            last_name="User",
        )
        self.admin_profile = UserProfile.objects.create(user = self.admin_user,is_active = True)
        
    def test_create_new_admin_account(self):
        """
        Ensure we can create a new admin object.
        """
        url = reverse('user-admin-register')
        data = {
            "email": "krishnababu@gmail.com",
            "first_name": "Zeta",
            "last_name": "Labs",
            "password": "Zeta1234",
            "password2": "Zeta1234",
            "contact_number": "98178916719"
        }
        response = self.client.post(url, data, format='json')
        new_user = User.objects.get(email='krishnababu@gmail.com')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 2)  # Initial admin + new user
        self.assertEqual(new_user.full_name, f"{data["first_name"]} {data['last_name']}")
        self.assertEqual(UserProfile.objects.get(user = new_user).contact_number, data["contact_number"])
        email = mail.outbox[0]
        self.assertEqual(email.to, [new_user.email])
        self.assertIn("Verify your email address", email.subject)  # Check that the subject is correct
        self.assertIn("Please verify your email by clicking the link below", email.body)  # Check that the email body contains the user's name
        
    def test_create_admin_with_existing_email(self):
        """
        Ensure that creating a user with an existing email fails.
        """
        url = reverse('user-admin-register')
        data = {
            "email": "admin@example.com",  # Already used by `self.admin_user`
            "first_name": "New",
            "last_name": "User",
            "password": "Test12345",
            "password2": "Test12345",
            "contact_number": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)  # Error should mention 'email'

    def test_create_admin_with_invalid_password(self):
        """
        Ensure that creating a user with an invalid password fails.
        """
        url = reverse('user-admin-register')
        data = {
            "email": "invalidpassword@gmail.com",
            "first_name": "Invalid",
            "last_name": "Password",
            "password": "123",  # Invalid password, too short
            "password2": "123",
            "contact_number": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_create_admin_with_mismatched_passwords(self):
        """
        Ensure that creating a user with mismatched passwords fails.
        """
        url = reverse('user-admin-register')
        data = {
            "email": "mismatch@gmail.com",
            "first_name": "Mismatch",
            "last_name": "Password",
            "password": "Password1234",
            "password2": "DifferentPassword1234",  # Passwords do not match
            "contact_number": "1234567890"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Check for either 'password' field error or 'non_field_errors'
        self.assertTrue(
            ('password' in response.data) or ('non_field_errors' in response.data),
            "Expected 'password' or 'non_field_errors' in the response."
        )

        # Further, verify the exact error messages if needed
        if 'password' in response.data:
            self.assertIn('password', response.data)  # Example: check for weak password error
        if 'non_field_errors' in response.data:
            self.assertIn('Password and Confirm Password does not match', response.data['non_field_errors'])
            
    def test_create_admin_with_missing_fields(self):
        """
        Ensure that creating a user with missing fields fails.
        """
        url = reverse('user-admin-register')
        data = {
            "email": "",  # Missing required field
            "first_name": "first",
            "last_name": "name",
            "password": "Password1234",
            "password2": "Password1234",
            "contact_number": "9811111111"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
        # self.assertIn('first_name', response.data)
        # self.assertIn('last_name', response.data)

    def test_admin_login(self):
        """
        Ensure that an admin user can log in successfully.
        """
        url = reverse('userAdmin-login')
        data = {
            "email": self.admin_user.email,
            "password": "Admin12345"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)  # Ensure JWT token is returned

    def test_admin_login_invalid_credentials(self):
        """
        Ensure that login with invalid credentials fails.
        """
        url = reverse('userAdmin-login')
        data = {
            "email": self.admin_user.email,
            "password": "WrongPassword"
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'Email or Password is not Valid')
