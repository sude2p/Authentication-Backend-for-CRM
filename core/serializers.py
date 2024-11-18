import os
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator
from django.utils.encoding import force_bytes,smart_str
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_str
from .utils import Util
from rest_framework.exceptions import ValidationError
from .manager import UserType
from .models import UserProfile
from django.db import transaction, IntegrityError
from django.conf import settings
from django.contrib.auth.password_validation import validate_password





User = get_user_model()
PASSWORD_MISMATCH_ERROR = "Password and Confirm Password does not match"

class AdminUserRegisterationViewSerializer(serializers.ModelSerializer):
    """
    Serializer for registering a new admin user, including email, password, 
    and contact number. Ensures that the passwords are validated and hashed 
    before creating the user, and checks for unique email and contact number.

    Fields:
        email (EmailField): The email address of the admin user.
        password (CharField): The password for the admin user (write-only).
        password2 (CharField): Confirmation password (write-only).
        contact_number (CharField): The admin user's contact number.

    Methods:
        validate(attrs): Validates that the two passwords match and ensures email 
                         and contact number are unique.
        create(validated_data): Creates a new admin user and their associated 
                                UserProfile, handling the user as inactive until 
                                email verification.
    """
    email  = serializers.EmailField(max_length=255)
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    contact_number = serializers.CharField(max_length=12, required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ['email','first_name','last_name','password', 'password2','contact_number']
        extra_kwargs = {'password':{'write_only':True}}
        
        
    # validationg password and confirm passsword while registration
    def validate(self, attrs):
        """
        Validates the input data, ensuring that the password fields match, 
        the email is unique, and the contact number is unique.
        """
        password = attrs.get('password')
        password2 = attrs.get('password2')
        contact_number = attrs.get('contact_number')
        # Check if passwords match
        if password != password2:
            raise serializers.ValidationError(PASSWORD_MISMATCH_ERROR)
        #check if emailid already exists:
        if User.objects.filter(email=attrs['email'].strip().lower()).exists():
            raise serializers.ValidationError({'email':'This email is already in use'})
        #check if contactnumber already exists:
        if UserProfile.objects.filter(contact_number=contact_number).exists():
            raise serializers.ValidationError({"contact_number": "This contact number is already in use."})
        return attrs
    
    def create(self, validated_data):
        """
        Creates a new admin user with the validated data and their corresponding 
        UserProfile. Marks the user as inactive and unverified until email verification.
        """
        validated_data.pop('password2')
        contact_number = validated_data.pop('contact_number')
            
        # Create UserAdmin instance
        try:
            with transaction.atomic():
                #create user_admin instance
                user_admin = User.objects.create_superuser(
                    email=validated_data['email'].strip().lower(),
                    first_name = validated_data['first_name'],
                    last_name = validated_data['last_name'],
                   
                )
                user_admin.set_password(validated_data['password'])
                user_admin.save()
                
                #create UserProfile instance
                UserProfile.objects.create(
                    user=user_admin,
                    contact_number=contact_number,
                    user_type = validated_data.get('user_type', UserType.ADMIN.name),
                    is_active=False , # User is inactive until email verification
                    is_verified=False,  # User is not verified yet
                    organization=None
                )
        except IntegrityError as e:
            raise serializers.ValidationError(str(e))
        return user_admin
            
    
class AdminUserResendRegistrationLinkSerializer(serializers.Serializer):
    """
    Serializer for resending the registration verification link to a user.

    This serializer validates the provided email, ensures that the user exists,
    and checks whether the user is already verified. If the user is found and
    not yet verified, the user object is added to the validated data for further processing.

    Fields:
        email (EmailField): The email address of the user requesting to resend the registration link.

    Methods:
        validate(attrs): 
            - Validates the email field to check if the user exists.
            - Ensures that the user is not already verified.
            - Adds the user to the validated data if all conditions are met.
    """
    email = serializers.EmailField(max_length=255)
    def validate(self, attrs):
        """
        Validates that the user with the provided email exists and is not already verified.

        Args:
            attrs (dict): The input data containing the email.

        Returns:
            dict: The validated data including the user object.

        Raises:
            serializers.ValidationError: If the user does not exist or is already verified.
        """
        email = attrs.get('email')
        try:
            user = User.objects.get(email=email)
            user_profile = UserProfile.objects.get(user=user)
            if user_profile.is_verified:
                raise serializers.ValidationError("User is already verified.")
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        # Add the user to the validated data
        attrs['user']= user
        return attrs
    
       
class AdminUserRegistrationEmailVerifySerializer(serializers.Serializer):
    """
    Serializer for verifying user email during registration.

    This serializer decodes the UID, checks the validity of the token, and verifies 
    the user's email. If the token and UID are valid, the user's profile is updated 
    to mark them as verified and active. Additionally, it publishes user details 
    to RabbitMQ for further processing.

    Methods:
        validate(attrs): 
            - Decodes the UID and validates the token.
            - Updates the user's profile if validation is successful.
            - Publishes user details to RabbitMQ for synchronization.
    """
    def validate(self, attrs):
        """
        Validates the UID and token provided in the request context, marking the user 
        as verified and active if the data is valid.

        Args:
            attrs (dict): The input data for validation.

        Returns:
            dict: The validated data if the user is successfully verified.

        Raises:
            serializers.ValidationError: If the UID or token is invalid, or if the user does not exist.
        """
        uid = self.context.get('uid')
        token = self.context.get('token')
        try:
            uid = force_str(urlsafe_base64_decode(uid))
            print(f'user_id: {uid}')
            user_admin = User.objects.get(pk=uid)
            print(f'user_admin: {user_admin}')
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
             raise serializers.ValidationError("Invalid UID")
        if user_admin is not None and default_token_generator.check_token(user_admin, token):
             user_profile = UserProfile.objects.get(user=user_admin)
             user_profile.is_verified = True
             user_profile.is_active = True
             user_profile.save()
             
             self.context['publish_to_rabbitmq']('platform_user_created', {
            'userId': user_admin.id,
            'email': user_admin.email,
            'firstName': user_admin.first_name,
            'lastName': user_admin.last_name,
            'isAdmin': user_admin.is_admin,
            'isStaff': user_admin.is_staff,
            'contactNumber': user_admin.userprofile.contact_number,
            'organizationId' : user_admin.userprofile.organizaton if user_admin.userprofile.organization else None,
            'userType' : user_admin.userprofile.user_type,
            'createdBy' : user_admin.userprofile.created_by if user_admin.userprofile.created_by else None,
            })
             return attrs
        else:
            raise serializers.ValidationError("Invalid token or user does not exist")  
         

class AdminUserVerifyOtpSerializer(serializers.Serializer):
    """
    Serializer for verifying an OTP (One-Time Password) during user authentication.

    This serializer ensures that the provided OTP is present and valid. It expects 
    the OTP to be a 6-character string and performs necessary validation checks.

    Attributes:
        otp (CharField): A 6-character OTP input field.
    """
    
    otp = serializers.CharField(max_length=6)

    def validate(self, attrs):
        """
        Validate the provided OTP.

        Ensures that the OTP is present and meets the expected format. This method can 
        be extended to include additional OTP validation logic (e.g., checking against 
        a database).

        Args:
            attrs (dict): The input data containing the OTP.

        Returns:
            dict: The validated input data including the OTP.

        Raises:
            serializers.ValidationError: If the OTP is missing or invalid.
        """
       
       
        otp = attrs.get('otp')
        
        if not otp:
            raise serializers.ValidationError("No OTP found")
        return attrs   


# user_admin login serializer
class AdminUserLoginSerializer(serializers.ModelSerializer):
    """
    Serializer for user login.

    This serializer handles the validation of user login credentials. It requires
    an email and password to authenticate a user.

    Fields:
        email (str): The email address of the user.
        password (str): The password of the user.

    Meta:
        model (User): The model associated with the serializer.
        fields (list): List of fields included in the serializer.
    """
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']
          
        
class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile.

    This serializer handles the representation of the user profile, specifically
    focusing on the contact number.

    Fields:
        contact_number (str): The contact number of the user.

    Meta:
        model (UserProfile): The model associated with the serializer.
        fields (list): List of fields included in the serializer.
    """
    class Meta:
        model = UserProfile
        fields = ['contact_number'] 
               
    
class AdminUserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for admin user profiles.

    This serializer is responsible for representing and updating user profile data.
    It includes user details such as ID, email, first name, last name, and the contact 
    number obtained from the related `UserProfile`. It ensures that the contact number 
    is unique across user profiles.

    Fields:
        id (int): The unique identifier for the user.
        email (str): The email address of the user.
        first_name (str): The first name of the user.
        last_name (str): The last name of the user.
        contact_number (str): The contact number of the user, fetched from the related `UserProfile`.

    Methods:
        get_contact_number(obj): Retrieves the contact number from the associated `UserProfile`.
        update(instance, validated_data): Updates the user details and optionally the contact number, 
        ensuring that the contact number is unique.

    Meta:
        model (User): The Django model associated with this serializer.
        fields (list): List of fields included in the serialized representation.
    """
    contact_number = serializers.SerializerMethodField() # Use a method field to get the contact number from the user profile
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'contact_number']

    def get_contact_number(self, obj):
        """Fetch the contact number from the related UserProfile."""
        # Fetch the contact_number from the related UserProfile
        user_profile = UserProfile.objects.filter(user=obj).first()
        return user_profile.contact_number if user_profile else None

    def update(self, instance, validated_data):
        """Update the User and UserProfile instances with validated data."""
        new_contact_number = self.initial_data.get('contact_number', None) 

        # Update User fields
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.save()

        # Update contact_number if provided
        if new_contact_number:
            user_profile, _ = UserProfile.objects.get_or_create(user=instance)
            # Check if the contact_number is different
            if new_contact_number != user_profile.contact_number:
                # Perform uniqueness validation only if contact_number has changed
                if UserProfile.objects.filter(contact_number=new_contact_number).exclude(user=instance).exists():
                    raise serializers.ValidationError({
                        "contact_number": "User profile with this contact number already exists."
                    })
                # Update the contact number field
                user_profile.contact_number = new_contact_number
                user_profile.save()
        return instance
    
        
        
class AdminUserPasswordChangeSerializer(serializers.ModelSerializer):
    """
    Serializer for changing an admin user's password.

    This serializer handles the validation and updating of a user's password, including
    verifying the old password and ensuring the new passwords match. It is intended for 
    use by admin users to update their own passwords.

    Fields:
        old_password (str): The current password of the user, used for verification.
        password (str): The new password for the user.
        password2 (str): A confirmation of the new password to ensure they match.

    Methods:
        validate(attrs): Validates the old password, checks if the new passwords match, 
        and updates the user's password if all checks pass.

    Meta:
        model (User): The Django model associated with this serializer.
        fields (list): List of fields included in the serialized representation.
    """
    old_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['old_password','password', 'password2']

    def validate(self, attrs):
        """
        Validates the password change request.

        Ensures that the old password is correct, the new passwords match, and updates
        the user's password if all checks pass.

        Args:
            attrs (dict): The input data containing the old and new passwords.

        Returns:
            dict: The validated input data including the old password, new password, and confirmation.

        Raises:
            serializers.ValidationError: If the old password is incorrect or the new passwords do not match.
        """
        old_password = attrs.get('old_password')
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user') # take user from context dictionary
        if not user.check_password(old_password):
            raise serializers.ValidationError("Old password is incorrect")
        if password != password2:
            raise serializers.ValidationError(PASSWORD_MISMATCH_ERROR)
        user.set_password(password)
        user.save()
        return attrs    
    
class AdminUserPasswordResetEmailSerializer(serializers.ModelSerializer):
    """
    Serializer for sending a password reset email to a user.

    This serializer handles the process of generating a password reset link and sending 
    it to the user's email address. The link includes a token that can be used to 
    reset the user's password.

    Fields:
        email (str): The email address of the user requesting a password reset.

    Methods:
        validate(attrs): Checks if the user with the provided email exists. If so, 
        generates a password reset link and sends it via email. If the user does not exist, 
        raises a validation error.

    Meta:
        model (User): The Django model associated with this serializer.
        fields (list): List of fields included in the serialized representation.
    """
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields =['email']

    def validate(self, attrs):
        """
        Validates the email provided for password reset.

        Args:
            attrs (dict): The input data containing the email.

        Returns:
            dict: The validated input data including the email.

        Raises:
            serializers.ValidationError: If the user with the provided email does not exist.
        """
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print(f'encoded uid: {uid}')
            token = PasswordResetTokenGenerator().make_token(user)
            print(f'password rest token:{token}')
            link = f'{settings.FRONTEND_URL}/api/userpassword/reset/'+ uid + '/'+ token
            print(f'password reset link:{link}')
            
            
            #send email
            body = 'Click the link to reset your password: ' + link
            data = {
                'subject': 'Reset Your Password',
                'body':body,
                'to_email':user.email,
            }
            Util.send_email(data)

            return attrs

        else:
            raise serializers.ValidationError('You are not a Registered user. Please register.')
        
        
class AdminUserPasswordResetSerializer(serializers.ModelSerializer):
    """
    Serializer for resetting a user's password using a token.

    This serializer handles the validation of new passwords and verifies the token 
    and user ID provided for resetting the password. It updates the user's password 
    if the token is valid and passwords match.

    Fields:
        password (str): The new password for the user.
        password2 (str): Confirmation of the new password.

    Methods:
        validate(attrs): Validates that the provided passwords match, the token is valid, 
        and the user ID is correct. If valid, updates the user's password. If not valid, 
        raises validation errors.

    Meta:
        model (User): The Django model associated with this serializer.
        fields (list): List of fields included in the serialized representation.
    """
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True) 
    class Meta:
        model = User
        fields = ['password', 'password2']

    def validate(self, attrs):
        """
        Validates the password reset request.

        Args:
            attrs (dict): The input data containing the new passwords.

        Returns:
            dict: The validated input data if successful.

        Raises:
            serializers.ValidationError: If passwords do not match, UID is invalid,
            or the token is invalid or expired.
        """
        
        password = attrs.get('password')
        password2 = attrs.get('password2')
        uid = self.context.get('uid')
        token = self.context.get('token')
        if password != password2:
            raise serializers.ValidationError(PASSWORD_MISMATCH_ERROR)
        try:
            uid = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid UID")
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise ValidationError('Token is not Valid or Expired')
        user.set_password(password)
        user.save()
        return attrs        
        
