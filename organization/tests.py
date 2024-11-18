# from django.test import TestCase
# from rest_framework import status
# from django.urls import reverse
# from django.contrib.auth import get_user_model
# from .models import Organization
# from unittest.mock import patch
# User = get_user_model()

# # Create your tests here.

# class OrganizationTest(TestCase):

#     def setUp(self):
#         self.admin_user = User.objects.create_superuser(
#             email="admin@example.com",
#             password="Admin12345",
#             first_name="Admin",
#             last_name="User"
#         )

#         self.non_admin_user = User.objects.create_user(
#             email="non_admin@example.com",
#             password="NonAdmin12345",
#             first_name="Non",
#             last_name="Admin"
#         )

#         self.organization_data = {
#             'name': 'Test Organization',
#             'description': 'This is a test organization',
#             'street': '123 Test St',
#             'postal_code': '12345',
#             'address': '123 Test St, Test City',
#             'email': 'test@organization.com',
#             'contact_number': '1234567890',
#             'province': 'Test Province',
#             'country': 'Test Country',
#             'website': 'http://testorganization.com',
#             'organization_type': 'Non-Profit',
#             'established_date': '2020-01-01',
#         }

#     # @patch('organization.views.publish_to_rabbit_mq')  # Mock RabbitMQ publishing
#     def test_create_organization_as_admin(self):
#         self.client.login(email="admin@example.com", password="Admin12345")
#         response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         self.assertEqual(Organization.objects.count(), 1)
#         # mock_publish.assert_called_once()  # Check that the RabbitMQ publish was called

#     def test_create_organization_as_non_admin(self):
#         self.client.login(email="non_admin@example.com", password="NonAdmin12345")
#         response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
#         self.assertEqual(Organization.objects.count(), 0)

#     def test_retrieve_organization_as_admin(self):
#         self.client.login(email="admin@example.com", password="Admin12345")
#         self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         organization = Organization.objects.first()
#         response = self.client.get(reverse('organization-profile', kwargs={'id': organization.id}))

#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(response.data['data']['name'], organization.name)

#     def test_retrieve_organization_profile_as_non_admin(self):
#         self.client.login(email="non_admin@example.com", password="NonAdmin12345")
#         self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         organization = Organization.objects.first()
#         response = self.client.get(reverse('organization-profile', kwargs={'id': organization.id}))
#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

#     def test_update_organization_as_admin(self):
#         self.client.login(email="admin@example.com", password="Admin12345")
#         self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         organization = Organization.objects.first()
#         update_data = {
#             'name': 'Updated Organization',
#             'description': 'Updated description',
#         }

#         response = self.client.put(reverse('organization-profile', kwargs={'id': organization.id}), update_data, format='json')

#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         organization.refresh_from_db()
#         self.assertEqual(organization.name, 'Updated Organization')

#     def test_update_organization_as_non_admin(self):
#         self.client.login(email="non_admin@example.com", password="NonAdmin12345")
#         self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         organization = Organization.objects.first()
#         update_data = {
#             'name': 'Updated Organization',
#             'description': 'Updated description',
#         }

#         response = self.client.put(reverse('organization-profile', kwargs={'id': organization.id}), update_data, format='json')

#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

#     def test_delete_organization_as_admin(self):
#         self.client.login(email="admin@example.com", password="Admin12345")
#         self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         organization = Organization.objects.first()
#         response = self.client.delete(reverse('organization-profile', kwargs={'id': organization.id}))

#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(Organization.objects.count(), 0)

#     def test_delete_organization_as_non_admin(self):
#         self.client.login(email="non_admin@example.com", password="NonAdmin12345")
#         self.client.post(reverse('organization-create'), self.organization_data, format='json')
#         organization = Organization.objects.first()
#         response = self.client.delete(reverse('organization-profile', kwargs={'id': organization.id}))

#         self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)     
        
        
        
from django.test import TestCase
from rest_framework import status
from django.urls import reverse
from django.contrib.auth import get_user_model
from .models import Organization

User = get_user_model()

class OrganizationTest(TestCase):

    def setUp(self):
        # Create an admin user
        self.admin_user = User.objects.create_superuser(
            email="admin@example.com",
            password="Admin12345",
            first_name="Admin",
            last_name="User"
        )

        # Create a non-admin user
        self.non_admin_user = User.objects.create_user(
            email="non_admin@example.com",
            password="NonAdmin12345",
            first_name="Non",
            last_name="Admin"
        )

        # Define organization data for tests
        self.organization_data = {
            'name': 'Test Organization',
            'description': 'This is a test organization',
            'street': '123 Test St',
            'postal_code': '12345',
            'address': '123 Test St, Test City',
            'email': 'test@organization.com',
            'contact_number': '1234567890',
            'province': 'Test Province',
            'country': 'Test Country',
            'website': 'http://testorganization.com',
            'organization_type': 'Non-Profit',
            'established_date': '2020-01-01',
        }

    def login_admin(self):
        """Helper method to login admin user."""
        self.client.login(email="admin@example.com", password="Admin12345")

    def login_non_admin(self):
        """Helper method to login non-admin user."""
        self.client.login(email="non_admin@example.com", password="NonAdmin12345")

    def test_create_organization_as_admin(self):
        self.login_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Organization.objects.count(), 1)

    def test_create_organization_as_non_admin(self):
        self.login_non_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Organization.objects.count(), 0)

    def test_retrieve_organization_as_admin(self):
        self.login_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        organization = Organization.objects.first()
        response = self.client.get(reverse('organization-profile', kwargs={'id': organization.id}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['data']['name'], organization.name)

    def test_retrieve_organization_as_non_admin(self):
        self.login_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        organization = Organization.objects.first()
        self.login_non_admin()
        response = self.client.get(reverse('organization-profile', kwargs={'id': organization.id}))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_organization_as_admin(self):
        self.login_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        organization = Organization.objects.first()
        update_data = {
            'name': 'Updated Organization',
            'description': 'Updated description',
        }
        response = self.client.put(reverse('organization-profile', kwargs={'id': organization.id}), update_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        organization.refresh_from_db()
        self.assertEqual(organization.name, 'Updated Organization')

    def test_update_organization_as_non_admin(self):
        self.login_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        organization = Organization.objects.first()
        self.login_non_admin()
        update_data = {
            'name': 'Updated Organization',
            'description': 'Updated description',
        }
        response = self.client.put(reverse('organization-profile', kwargs={'id': organization.id}), update_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_organization_as_admin(self):
        self.login_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        organization = Organization.objects.first()
        response = self.client.delete(reverse('organization-profile', kwargs={'id': organization.id}))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Organization.objects.count(), 0)

    def test_delete_organization_as_non_admin(self):
        self.login_admin()
        response = self.client.post(reverse('organization-create'), self.organization_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        organization = Organization.objects.first()
        self.login_non_admin()
        response = self.client.delete(reverse('organization-profile', kwargs={'id': organization.id}))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)