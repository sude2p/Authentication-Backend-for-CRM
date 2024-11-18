import os
from rest_framework import serializers
from django.db import transaction, IntegrityError
from core.utils import Util
from rest_framework.exceptions import ValidationError
from core.models import User, UserProfile
from .models import Organization
from django.db import transaction, IntegrityError
from core.utils import UserType
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str
from django.utils.encoding import force_bytes
from django.urls import reverse
from core.publisher import publish_to_rabbitmq
from rest_framework.response import Response
from rest_framework import status
from core.views import get_tokens_for_user
from django.conf import settings


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserProfile model.

    This serializer is responsible for validating and serializing the contact information
    associated with a user profile.

    Attributes:
        contact_number (str): The user's contact number, which will be validated and
                              serialized through this serializer.

    Methods:
        create(validated_data): Creates a new UserProfile instance using the validated data.
        update(instance, validated_data): Updates an existing UserProfile instance
                                           with the validated data.

    Meta:
        model (UserProfile): The model that this serializer is based on.
        fields (tuple): The fields of the UserProfile model to be serialized; in this case,
                        only the contact_number field is included.
    """
    class Meta:
        model = UserProfile
        fields = ("contact_number",)

class OrgUserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating organization user information.

    This serializer handles the validation and serialization of user details, including 
    updating the user's profile information. It allows the organization admin to update 
    the basic user fields and the associated user profile fields in a single request.

    Attributes:
        userprofile (UserProfileSerializer): A nested serializer for the user's profile data.

    Methods:
        update(instance, validated_data): Updates an existing User instance with the validated
                                           data and saves any changes to the associated 
                                           UserProfile instance.

    Meta:
        model (User): The model that this serializer is based on.
        fields (list): The fields of the User model to be serialized, including the user's 
                       email, first name, last name, and nested user profile information.
    """
    userprofile = UserProfileSerializer()
    class Meta:
        model = User
        fields = [
            "email",
            "first_name",
            "last_name",
            "userprofile",
        ]
        
    def update(self, instance, validated_data):
        """
        Updates an existing User instance with the validated data.

        This method updates the fields of the User instance with the provided 
        validated data and saves the changes. If user profile data is included, 
        it also updates the corresponding UserProfile instance.

        Args:
            instance (User): The User instance to be updated.
            validated_data (dict): A dictionary of validated data, which includes 
                                   user fields and user profile data.

        Returns:
            User: The updated User instance.

        Raises:
            ValidationError: If the user profile data is invalid when saving.
        """
        userprofile_data = validated_data.pop('userprofile', None)
        # Update User instance fields
        instance.email = validated_data.get('email', instance.email)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.save()
        # Update UserProfile instance if it exists
        if userprofile_data:
            userprofile_serializer = UserProfileSerializer(instance.userprofile, data=userprofile_data)
            if userprofile_serializer.is_valid():
                userprofile_serializer.save()

        return instance


class UserAdminSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model used in admin interfaces.

    This serializer provides a simplified representation of the User model for administrative 
    purposes. It includes essential fields that are relevant for managing user accounts.

    Attributes:
        id (int): The unique identifier for the user.
        email (str): The email address of the user.

    Methods:
        None: This class uses the default behavior provided by the ModelSerializer.

    Meta:
        model (User): The model that this serializer is based on.
        fields (list): The fields of the User model to be serialized, specifically the user's 
                       id and email.
    """

    class Meta:
        model = User
        fields = ["id", "email"]


class OrganizanizationCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating an Organization instance.

    This serializer handles the validation and creation of an Organization object, ensuring that 
    required fields are provided and that certain constraints are met.

    Attributes:
        created_by (UserAdminSerializer): The user who created the organization, set as read-only.

    Fields:
        - created_by (UserAdminSerializer): The user creating the organization.
        - name (str): The name of the organization.
        - description (str): A description of the organization.
        - street (str): The street address of the organization.
        - postal_code (str): The postal code of the organization's location.
        - address (str): The full address of the organization.
        - email (str): The email address of the organization (must be unique).
        - contact_number (str): The contact number for the organization (must be unique).
        - province (str): The province where the organization is located.
        - country (str): The country where the organization is based.
        - website (str): The organization's website URL.
        - organization_type (str): The type of organization.
        - established_date (date): The date the organization was established.

    Methods:
        validate(attrs): Validates input data for unique constraints.
        create(validated_data): Creates a new Organization instance and updates the UserProfile.

    Raises:
        ValidationError: If any of the validation checks fail.
    """

    created_by = UserAdminSerializer(read_only=True)

    class Meta:
        model = Organization
        fields = [
            "created_by",
            "name",
            "description",
            "street",
            "postal_code",
            "address",
            "email",
            "contact_number",
            "province",
            "country",
            "website",
            "organization_type",
            "established_date",
        ]

    def validate(self, attrs):
        """
        Validates that the provided email, contact_number, and name are unique.

        Args:
            attrs (dict): The input data to validate.

        Returns:
            dict: The validated attributes.

        Raises:
            ValidationError: If the email, contact_number, or name already exists.
        """
        email = attrs.get("email")
        name = attrs.get("name")
        contact_number = attrs.get("contact_number")
        if Organization.objects.filter(email=email).exists():
            raise ValidationError(
                {
                    "status": "error",
                    "message": "Organization email already exists. Provide a new one.",
                }
            )
        if Organization.objects.filter(contact_number=contact_number).exists():
            raise ValidationError(
                {
                    "status": "error",
                    "message": "Organization contact number already exists. Provide a new one.",
                }
            )
        if Organization.objects.filter(name=name).exists():
            raise ValidationError(
                {
                    "status": "error",
                    "message": "Organization with this name already exists. Provide a new one"
                }
            )   
        return attrs

    def create(self, validated_data):
        """
        Creates a new Organization instance and links it to the current user.

        Args:
            validated_data (dict): The validated data for creating the organization.

        Returns:
            Organization: The newly created Organization instance.

        Raises:
            ValidationError: If an IntegrityError occurs during creation.
        """
        user = self.context["user"]
        validated_data["created_by"] = user
        try:
            with transaction.atomic():
                organization = Organization.objects.create(**validated_data)
                # Update UserProfile to link to the new organization
                UserProfile.objects.filter(user=user).update(
                    organization=organization.id
                )
                return organization

        except IntegrityError as e:
            raise serializers.ValidationError(str(e))


class OrganizationProfleSerializer(serializers.ModelSerializer):
    """
    Serializer for retrieving and updating an Organization instance.

    This serializer provides an interface for both getting details of an Organization 
    and updating its fields. It includes validation for the fields being updated and 
    restricts the 'created_by' field to read-only access.

    Attributes:
        created_by (UserAdminSerializer): The user who created the organization, set as read-only.

    Fields:
        - id (int): The unique identifier of the organization.
        - created_by (UserAdminSerializer): The user who created the organization.
        - name (str): The name of the organization.
        - description (str): A description of the organization.
        - street (str): The street address of the organization.
        - postal_code (str): The postal code of the organization's location.
        - address (str): The full address of the organization.
        - email (str): The email address of the organization.
        - contact_number (str): The contact number for the organization.
        - province (str): The province where the organization is located.
        - country (str): The country where the organization is based.
        - website (str): The organization's website URL.
        - organization_type (str): The type of organization.
        - kyc_verified (bool): Indicates whether the organization's KYC (Know Your Customer) process is verified.
        - established_date (date): The date the organization was established.

    Methods:
        update(instance, validated_data): Updates the Organization instance with validated data.

    Raises:
        ValidationError: If any of the validation checks fail during the update process.
    """

    created_by = UserAdminSerializer(read_only=True)

    class Meta:
        model = Organization
        fields = [
            "id",
            "created_by",
            "name",
            "description",
            "street",
            "postal_code",
            "address",
            "email",
            "contact_number",
            "province",
            "country",
            "website",
            "organization_type",
            "kyc_verified",
            "established_date",
        ]  # need to add logo field later

    def update(self, instance, validated_data):
        """
        Updates an existing Organization instance with the provided validated data.

        Args:
            instance (Organization): The instance of the Organization to update.
            validated_data (dict): The validated data to update the Organization instance with.

        Returns:
            Organization: The updated Organization instance.

        Raises:
            ValidationError: If there are any validation errors during the update process.
        """
        # Call the parent class's update method
        return super().update(instance, validated_data)


class OrgUserListSerializer(serializers.ModelSerializer):
    """
    Serializer for listing user profiles associated with an organization.

    This serializer provides a representation of user profiles, including
    relevant user details such as email, first name, last name, and contact
    number. It also includes a method for determining the roles of the user.

    Attributes:
        email (str): The email address of the user, retrieved from the user model.
        id (int): The unique identifier of the user, retrieved from the user model.
        first_name (str): The first name of the user, retrieved from the user model.
        last_name (str): The last name of the user, retrieved from the user model.
        roles (str): The roles associated with the user, determined by the get_roles method.

    Fields:
        - id (int): The unique identifier of the user.
        - email (str): The email address of the user.
        - first_name (str): The first name of the user.
        - last_name (str): The last name of the user.
        - contact_number (str): The contact number for the user.
        - roles (str): The roles associated with the user.

    Methods:
        get_roles(obj): Returns the roles associated with the user, currently hardcoded to "admin".
    """

    email = serializers.StringRelatedField(source="user.email")
    id = serializers.StringRelatedField(source="user.id")
    first_name = serializers.StringRelatedField(source="user.first_name")
    last_name = serializers.StringRelatedField(source="user.last_name")
    roles = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = ["id", "email", "first_name", "last_name", "contact_number", "roles"]

    # need to change later
    def get_roles(self, obj):
        """
        Retrieves the roles associated with the user.

        Args:
            obj (UserProfile): The UserProfile instance for which to retrieve roles.

        Returns:
            str: The roles associated with the user, currently hardcoded to "admin".

        Note:
            This method will be updated later to dynamically retrieve the user's roles.
        """
        return f"admin"

#-----------------------------------------------------------------------------------------------------------------------
class OrgUserProfileSerializer(serializers.ModelSerializer):
    """
Serializer for the UserProfile model associated with an organization.

This serializer is used to manage the representation of user profile
data, specifically when retrieving or updating information related to
a user within an organization. It includes fields for contact details,
verification status, user type, and associations with the creator and organization.

Attributes:
    contact_number (str): The user's contact number.
    is_active (bool): Indicates whether the user's profile is active.
    is_verified (bool): Indicates whether the user's profile has been verified.
    user_type (str): The type of user (e.g., admin, staff).
    created_by (User): The user who created this profile.
    organization (Organization): The organization associated with this user profile.

Fields:
    - contact_number (str): The contact number for the user.
    - is_active (bool): Whether the user profile is currently active.
    - is_verified (bool): Whether the user profile has been verified.
    - user_type (str): The type/category of the user.
    - created_by (User): The user who created this profile; read-only.
    - organization (Organization): The organization linked to this user profile; read-only.

Read-Only Fields:
    - is_verified: This field cannot be updated through the serializer.
    - is_active: This field cannot be updated through the serializer.
    - user_type: This field cannot be updated through the serializer.
    - created_by: This field cannot be updated through the serializer.
    - created_at: Timestamp of when the user profile was created; read-only.
    - updated_at: Timestamp of the last update to the user profile; read-only.
    - organization: The organization associated with the user profile; read-only.
"""
    class Meta:
        model = UserProfile
        fields = [
            "contact_number",
            "is_active",
            "is_verified",
            "user_type",
            "created_by",
            "organization",
        ]
        read_only_fields = [
            "is_verified",
            "is_active",
            "user_type",
            "created_by",
            "created_at",
            "updated_at",
            "organization",
        ]


class OrgUserSerializer(serializers.ModelSerializer):
    """
    Serializer for managing organization user data.

    This serializer handles the creation and update of User instances
    associated with an organization, including their profiles. It validates
    and processes input data, manages email invitations for new users, 
    and ensures relationships between users, profiles, and organizations.

    Attributes:
        profile (OrgUserProfileSerializer): Nested serializer for user profile data.
        email (str): The email address of the user.

    Fields:
        - id (int): The unique identifier for the user.
        - email (str): The email address of the user.
        - first_name (str): The first name of the user.
        - last_name (str): The last name of the user.
        - is_staff (bool): Indicates if the user has staff privileges; read-only.
        - is_admin (bool): Indicates if the user has admin privileges; read-only.
        - profile (OrgUserProfileSerializer): The user's profile data.

    Methods:
        send_email_invite(user): 
            Sends an email invitation to the newly created user to verify their email and set their password.
        
        create(validated_data): 
            Creates a new User instance along with a linked UserProfile instance.
            Sends an email invitation upon successful creation.
        
        update(instance, validated_data): 
            Updates an existing User instance and its associated UserProfile instance with the provided data.
    """
    profile = OrgUserProfileSerializer(source="userprofile", partial=True)
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "is_staff",
            "is_admin",
            "profile",
        ]
        read_only_fields = ["is_staff", "is_admin"]

    @staticmethod
    def send_email_invite(user):
        """
        Sends an email verification invitation to a newly created user.

        This method generates a token and a unique URL for email verification,
        and sends the email containing the verification link.

        Args:
            user (User): The user instance to send the email to.
        """
        token = default_token_generator.make_token(user)
        print(f"token: {token}")
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        print(f"uid: {uid}")  # for debugging
        verification_url = reverse(
            "org-user-email-password-verify", kwargs={"uid": uid, "token": token}
        )
        full_url = f"{settings.FRONTEND_URL}/{verification_url}"
        body = f"Hi {user.first_name},\n\nPlease verify your email by clicking the link below and get redirected to set your password.\n{full_url}"
        data = {
            "subject": "Verify your email address",
            "body": body,
            "to_email": user.email,
        }
        Util.send_email(data)

    def create(self, validated_data):
        """
        Creates a new user and their associated profile.

        This method also sends an email verification invitation to the newly created user.

        Args:
            validated_data (dict): The validated input data for creating the user.

        Returns:
            User: The created user instance.

        Raises:
            serializers.ValidationError: If the user profile creation fails or if there is an IntegrityError.
        """
        print(f"validated_data: {validated_data}")

        # profile_data = validated_data.pop("profile", {})
        profile_data = validated_data.get("userprofile", {})
        print(f"Profile Data: {profile_data}")  # for debugging
        contact_number = profile_data.get("contact_number", "")
        is_active = profile_data.get("is_active", False)
        is_verified = profile_data.get("is_verified", False)
        user_type = profile_data.get("user_type", UserType.USER.name)
        # Get the current user (admin user who is creating the new org user)
        admin_user = self.context["user"]
        print(f"User Admin Profile: {admin_user}")  # for debugging

        # Fetch the UserProfile of the request user (admin)
        try:
            created_by_profile = UserProfile.objects.get(user=admin_user)
            print(f"created_by_profile: {created_by_profile}")
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError(
                "The admin user does not have a UserProfile."
            )

        try:
            organization_id = self.context.get("organization_id")
            organization = Organization.objects.get(created_by=admin_user, id=organization_id)
            if organization.created_by == admin_user:
                print(f"Organization: {organization}")
        except Organization.DoesNotExist:
            organization = None
            print("No organization found for the user_admin.")  # for debugging

        try:
            with transaction.atomic():
                user = User.objects.create(
                    email=validated_data["email"].strip().lower(),
                    first_name=validated_data["first_name"],
                    last_name=validated_data["last_name"],
                    is_staff=validated_data.get("is_staff", False),
                    is_admin=validated_data.get("is_admin", False),
                )

                # Create the UserProfile linked to this user

                UserProfile.objects.create(
                    user=user,
                    contact_number=contact_number,
                    is_active=is_active,
                    is_verified=is_verified,
                    user_type=user_type,
                    organization=organization,
                    created_by=created_by_profile,
                )
                # Send the verification email
                OrgUserSerializer.send_email_invite(user)

        except IntegrityError as e:
            raise serializers.ValidationError(str(e))
        return user

    def update(self, instance, validated_data):
        """
        Updates an existing user and their associated profile.

        This method takes the validated data and updates the User instance and the UserProfile instance.

        Args:
            instance (User): The existing user instance to update.
            validated_data (dict): The validated input data for updating the user.

        Returns:
            User: The updated user instance.
        """

        print(f"instance: {instance}")
        print(f"validated_data: {validated_data}")
        # Call the parent class's update method
        # user_data = validated_data.pop("userprofile", {})
        # Update User instance
        user_instance = instance.user  # Access the related User instance
        user_instance.email = (
            validated_data.get("email", user_instance.email).strip().lower()
        )
        user_instance.first_name = validated_data.get(
            "first_name", user_instance.first_name
        )
        user_instance.last_name = validated_data.get(
            "last_name", user_instance.last_name
        )
        user_instance.save()  # Save the User instance

        # Update UserProfile instance
        
        profile = instance
        profile.contact_number = validated_data.get(
            "contact_number", profile.contact_number
        )
        profile.is_active = validated_data.get("is_active", profile.is_active)
        profile.is_verified = validated_data.get("is_verified", profile.is_verified)
        profile.user_type = validated_data.get("user_type", profile.user_type)
        profile.save()  # Save the UserProfile instance

        return instance

#---------------------------------------------------------------------------------------------------


       


class OrgUserEmailRegistrationVerificationSerializer(serializers.Serializer):
    """
    Serializer for verifying email registration for organization users.

    This serializer handles the process of verifying a user's email address,
    setting a password, and activating the user's account after they click 
    on a verification link.

    Attributes:
        password (str): The password to be set for the user.
        password2 (str): A confirmation of the password.

    Methods:
        validate(attrs):
            Validates the UID and token from the verification link,
            ensuring they correspond to a valid user and that the passwords match.
        
        create(validated_data):
            Sets the user's password, activates the user account,
            updates the user profile, and generates JWT tokens for authentication.
    """
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """
        Validates the incoming data for email registration verification.

        This method checks if the UID and token are valid, verifies that 
        the user exists, checks the token's validity, and ensures that 
        the two password fields match.

        Args:
            attrs (dict): The validated input data.

        Returns:
            dict: The validated attributes including the organization user.

        Raises:
            ValidationError: If the UID is invalid, the token is invalid/expired, 
                             or the passwords do not match.
        """
        uid = self.context.get("uid")
        token = self.context.get("token")
        print(f"token: {token}")  # for debugging

        try:
            uid = force_str(urlsafe_base64_decode(uid))
            print(f"user_id: {uid}")  # for debugging
            org_user = User.objects.get(id=uid)
            print(f"org_user: {org_user}")  # for debugging
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise ValidationError("Invalid Uid")

        # Check token validity
        if not default_token_generator.check_token(org_user, token):
            raise ValidationError("Invalid or expired token")

        # Check password match
        password = attrs.get("password")
        password2 = attrs.get("password2")
        if password != password2:
            raise ValidationError("Passwords do not match")

        attrs["org_user"] = org_user
        return attrs

    def create(self, validated_data):
        """
        Creates the user account after verification.

        This method sets the user's password, activates the user account,
        updates the user profile, and generates JWT tokens for the user.

        Args:
            validated_data (dict): The validated input data containing 
                                   the organization user and password.

        Returns:
            dict: A dictionary containing the generated JWT tokens.

        Raises:
            ValidationError: If there is an error while saving the user 
                             or profile.
        """
        org_user = validated_data.get("org_user")
        password = validated_data.get("password")
        # Set password and activate user
        org_user.set_password(password)
        org_user.is_active = True
        org_user.is_staff = True
        org_user.save()
        # Update UserProfile if necessary
        user_profile = org_user.userprofile
        user_profile.is_active = True
        user_profile.is_verified = True
        user_profile.save()
        # Generate and return JWT tokens
        token = get_tokens_for_user(org_user)
        return token


class OrgUserLoginSerializer(serializers.ModelSerializer):
    """
    Serializer for handling the login process of organization users.

    This serializer is responsible for validating the user's email and password
    during the login process. It also provides the organization ID associated 
    with the user, allowing for better context during authentication.

    Attributes:
        organization (str): The ID of the organization the user belongs to.
        email (str): The email address of the user attempting to log in.
        password (str): The user's password for authentication (write-only).

    Methods:
        validate_password(password):
            Validates the provided password against the user's account.
    """

    organization = serializers.CharField(
        source="userprofile.organization.id", read_only=True
    )
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ["organization", "email", "password"]
        extra_kwargs = {"password": {"write_only": True}}


class OrgUserPasswordChangeSerializer(serializers.ModelSerializer):
    """
    Serializer for changing the password of an organization user.

    This serializer handles the validation of the old password, checks that
    the new password is confirmed correctly, and updates the user's password.

    Attributes:
        old_password (str): The current password of the user (write-only).
        password (str): The new password for the user (write-only).
        password2 (str): A confirmation of the new password (write-only).

    Methods:
        validate(attrs):
            Validates the old password and checks if the new passwords match.
    """
    old_password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        model = User
        fields = ["old_password", "password", "password2"]

    def validate(self, attrs):
        """
        Validates the password change request.

        This method checks that the provided old password is correct and that
        the new password matches the confirmation.

        Args:
            attrs (dict): A dictionary containing the old password and new passwords.

        Returns:
            dict: The validated data.

        Raises:
            serializers.ValidationError: If the old password is incorrect or if the
            new passwords do not match.
        """
        old_password = attrs.get("old_password")
        password = attrs.get("password")
        password2 = attrs.get("password2")
        user = self.context.get("request").user
        print(f"user:{user}")
        if not user.check_password(old_password):
            raise serializers.ValidationError("Old password is not correct")
        if password != password2:
            raise serializers.ValidationError("Password does not match")
        user.set_password(password)
        user.save()
        return attrs


class OrgUserInviteEmailSerializer(serializers.ModelSerializer):
    """
Serializer for inviting organization users via email.

This serializer allows for the batch creation of organization users
by accepting a list of email addresses. If the email already exists,
it skips that address. The serializer also sends an invitation email
to newly created users.

Attributes:
    email (list): A list of email addresses to invite (write-only).

Methods:
    create(validated_data):
        Creates new users for the provided email addresses and sends
        an invitation email to each new user.
"""
    email = serializers.ListField(child=serializers.EmailField(), write_only=True)

    class Meta:
        model = User
        fields = ["email"]

    def create(self, validated_data):
        """
        Creates new users based on the provided email addresses.

        Args:
            validated_data (dict): The validated data containing email addresses.

        Returns:
            list: A list of newly created User instances.
        """
        emails = validated_data["email"]
        admin_user = self.context["request"].user
        new_created_users = []
            
        for email in emails:
            if User.objects.filter(email=email).exists():
                print(f"Email {email} already exists. Skipping.") #for testing
                continue
            try:
                with transaction.atomic():
                    new_user = User.objects.create(email=email)
                    UserProfile.objects.create(
                        user=new_user,
                        created_by=admin_user.userprofile,
                        organization=admin_user.userprofile.organization,
                    )
                    OrgUserSerializer.send_email_invite(new_user)
                    new_created_users.append(new_user)
            except Exception as exc:
                print("Error: ", str(exc), "in row")
                pass # Proceed with the next email
        return new_created_users


class OrgUserInviteProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for managing user profile details during organization user invitations.

    This serializer is responsible for validating and serializing the
    UserProfile model associated with invited organization users. It ensures
    that only the appropriate fields can be written to, while others are read-only.

    Attributes:
        contact_number (str): The contact number of the user.
        is_active (bool): Indicates if the user profile is active.
        is_verified (bool): Indicates if the user's email/identity is verified.
        user_type (str): The type of user (e.g., admin, regular).
        created_by (UserProfile): The user profile of the admin who created this profile.
        organization (Organization): The organization to which this user belongs.
    """
    class Meta:
        model = UserProfile
        fields = [
            "contact_number",
            "is_active",
            "is_verified",
            "user_type",
            "created_by",
            "organization",
        ]
        read_only_fields = [
            "is_verified",
            "is_active",
            "user_type",
            "created_by",
            "created_at",
            "updated_at",
            "organization",
        ]


class OrgUserInviteSerializer(serializers.ModelSerializer):
    """
    Serializer for inviting organization users.

    This serializer handles the creation and updating of organization users and their associated
    profiles. It validates the input data, creates new users in the database, links their profiles,
    and sends verification emails upon user creation. 

    Attributes:
        profile (OrgUserInviteProfileSerializer): Nested serializer for the user's profile data.
    """
    profile = OrgUserInviteProfileSerializer(source="userprofile", partial=True)

    class Meta:
        model = User
        fields = ["email"]

    def create(self, validated_data):
        """
        Create a new organization user and associated profile.

        This method extracts profile data from the validated input, checks the existence of the 
        admin user's profile and organization, and creates a new user along with a linked 
        user profile. It also sends a verification email to the newly created user.

        Args:
            validated_data (dict): The validated input data containing user details and profile info.

        Returns:
            User: The newly created User instance.

        Raises:
            serializers.ValidationError: If the admin user does not have a UserProfile, or if there 
                                          is an integrity error while creating the user or profile.
        """

        profile_data = validated_data.pop("profile", {})
        contact_number = profile_data.get("contact_number") if profile_data else None
        is_active = profile_data.get("is_active", False)
        is_verified = profile_data.get("is_verified", False)
        user_type = profile_data.get("user_type", UserType.USER.name)
        # Get the current user (admin user who is creating the new org user)
        admin_user = self.context["request"].user
        print(f"User Admin Profile: {admin_user}")  # for debugging

        # Fetch the UserProfile of the request user (admin)
        try:
            created_by_profile = UserProfile.objects.get(user=admin_user)
            print(f"created_by_profile: {created_by_profile}")
        except UserProfile.DoesNotExist:
            raise serializers.ValidationError(
                "The admin user does not have a UserProfile."
            )

        try:
            organization = Organization.objects.get(created_by=admin_user)
            print(f"Organization: {organization}")
        except Organization.DoesNotExist:
            organization = None
            print("No organization found for the user_admin.")  # for debugging

        try:
            with transaction.atomic():
                user = User.objects.create(
                    email=validated_data["email"].strip().lower(),
                    first_name=validated_data["first_name"],
                    last_name=validated_data["last_name"],
                    is_staff=validated_data.get("is_staff", False),
                    is_admin=validated_data.get("is_admin", False),
                )

                # Create the UserProfile linked to this user

                UserProfile.objects.create(
                    user=user,
                    contact_number=contact_number,
                    is_active=is_active,
                    is_verified=is_verified,
                    user_type=user_type,
                    organization=organization,
                    created_by=created_by_profile,
                )
                # Send the verification email
                OrgUserSerializer.send_email_invite(user)

        except IntegrityError as e:
            raise serializers.ValidationError(str(e))
        return user

    def update(self, instance, validated_data):
        """
        Update an existing organization user and their profile.

        This method updates the specified fields of the User instance and the associated 
        UserProfile instance. It saves the changes to the database.

        Args:
            instance (User): The User instance to update.
            validated_data (dict): The validated input data containing updated user details and profile info.

        Returns:
            User: The updated User instance.

        Raises:
            serializers.ValidationError: If there are any validation issues during the update process.
        """
        # Call the parent class's update method
        profile_data = validated_data.pop("profile", {})
        instance.email = validated_data.get("email", instance.email).strip().lower()
        instance.first_name = validated_data.get("first_name", instance.first_name)
        instance.last_name = validated_data.get("last_name", instance.last_name)
        instance.save()
        if profile_data:
            profile = instance.userprofile
            profile.is_active = profile_data.get("is_active", profile.is_active)
            profile.is_verified = profile_data.get("is_verified", profile.is_verified)
            profile.user_type = profile_data.get("user_type", profile.user_type)
            profile.contact_number = profile_data.get(
                "contact_number", profile.contact_number
            )
            profile.save()

        return super().update(instance, validated_data)


class ImportOrgUserSerializer(serializers.Serializer):
    """
    Serializer for importing organization users from a CSV file.

    This serializer is responsible for validating the uploaded CSV file that contains 
    organization user data. It ensures that the uploaded file is of the correct format 
    (CSV) before further processing.

    Attributes:
        file (FileField): The uploaded CSV file containing user data.
    """
    file = serializers.FileField()
    

    def validate_file(self, value):
        """
        Validate the uploaded file to ensure it is a CSV.

        This method checks the file extension of the uploaded file. If the file does not 
        end with '.csv', it raises a validation error.

        Args:
            value (UploadedFile): The uploaded file to validate.

        Returns:
            UploadedFile: The validated file, if it is a CSV.

        Raises:
            serializers.ValidationError: If the file does not have a '.csv' extension.
        """
        if not value.name.endswith(".csv"):
            raise serializers.ValidationError("File must be a CSV")
        return value

    

class OrgUserUpdateUserProfileDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ["contact_number"]


class OrgUserUpdateUserSerializer(serializers.ModelSerializer):
    profile = OrgUserUpdateUserProfileDetailsSerializer(partial=True)

    class Meta:
        model = User
        fields = ["first_name", "last_name", "profile"]


class UserProfileFieldCheckSerializer(serializers.Serializer):
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    contact_number = serializers.CharField()
