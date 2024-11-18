import os
import pyotp
from django.shortcuts import render
from .renderer import UserRenderer
from rest_framework import views
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (AdminUserRegisterationViewSerializer, AdminUserLoginSerializer, AdminUserProfileSerializer,
                          AdminUserRegistrationEmailVerifySerializer, AdminUserPasswordChangeSerializer, AdminUserPasswordResetEmailSerializer,
                          AdminUserPasswordResetSerializer, AdminUserResendRegistrationLinkSerializer, AdminUserVerifyOtpSerializer)
from rest_framework.response import Response
from .models import UserProfile
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from .permissions import IsAdminOrSelf, IsOrganizationMember
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from .utils import Util
from django.contrib.auth import logout
from .publisher import publish_to_rabbitmq
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.generics import GenericAPIView
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.conf import settings



# Create your views here.

User = get_user_model()

@require_GET
def get_user(request, pk):
    """
    Retrieve user details by primary key.

    Args:
        request (HttpRequest): The HTTP request object.
        pk (int): The primary key of the user to retrieve.

    Returns:
        JsonResponse: A JSON response containing user details or an error message if the user is not found.
    """
    try:
        user = User.objects.get(id=pk)
        userprofile = user.userprofile
        data = {
            'id': user.id,
            'email': user.email,
            'is_admin': user.is_admin,
            'is_staff': user.is_staff,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'contact_number': userprofile.contact_number
            # Add other fields you need
        }
        return JsonResponse(data)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)


# Generate token manually
def get_tokens_for_user(user):
    """
    Generate JWT tokens for the specified user, including additional user information.

    Args:
        user (User): The user for whom the tokens are generated.

    Returns:
        dict: A dictionary containing the refresh token, access token, 
              organization ID, email, and user ID.
    """
    
    refresh = RefreshToken.for_user(user)
    # Retrieve the associated UserProfile to get organization_id
    user_profile = UserProfile.objects.get(user=user)
    organization_id = user_profile.organization.id if user_profile.organization else None
    email = user.email
    refresh['organization_id'] = organization_id
    refresh['email'] = email
    
    refresh['user_id'] = user.id
   
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
    
 # Generate email verification token and URL
def send_verification_email(user):
    """
    Generate and send a verification email to the specified user.

    Args:
        user (User): The user to receive the verification email.

    This function creates a verification token and URL, constructs the email body, 
    and sends the email using the `Util.send_email` method.
    """
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.id))
    full_url = f"{settings.FRONTEND_URL}/verify-email/{uid}/{token}/"
    body = f"Hi {user.first_name},\n\nPlease verify your email by clicking the link below:\n{full_url}"
    data = {
                'subject': 'Verify your email address',
                'body':body,
                'to_email':user.email,
            }
    Util.send_email(data)
      
    
    
#admin user create
class AdminUserRegistrationView(views.APIView):
    """
    Handle user registration requests made by admins.

    This view processes POST requests to register a new user, validates the 
    provided data using the AdminUserRegistrationViewSerializer, creates a new 
    user, sends a verification email, and publishes a user creation event to 
    RabbitMQ.

    Methods:
        post(request): Register a new user, send a verification email, and 
                       publish an event to RabbitMQ.
    """
    renderer_classes = [UserRenderer]
    
    def post(self,request):
        """
        Handle user registration and send a verification email.

        Validates the incoming registration data, creates a new user, and 
        sends a verification email if the user's profile is not verified. 
        If successful, it returns a success response; otherwise, it returns 
        an error response.

        Args:
            request (Request): The incoming HTTP request containing the user 
                               registration data.

        Returns:
            Response: A success or error response with appropriate status codes.
        """
        serializer = AdminUserRegisterationViewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_admin = serializer.save()
        # Send verification email
        try:
            userprofile = user_admin.userprofile
            if not userprofile.is_verified:
                send_verification_email(user_admin)
                return Response({'status':'success', 'message':'User Registration Link has been sent.Please check your Email.'}, 
                                status=status.HTTP_201_CREATED) 
        except:
            return Response({'status':'error', 'message':'User Registration Link can not be sent.'}, 
                        status=status.HTTP_400_BAD_REQUEST)    
        
      
       

class AdminUserRegistrationLinkResendView(views.APIView):
    """
    Resend the user registration verification link.

    This view handles POST requests to resend the verification email 
    for user registration. It uses the AdminUserResendRegistrationLinkSerializer 
    to validate the request data, retrieves the user, and sends a new verification 
    email.

    Methods:
        post(request): Validates input data, retrieves the user, 
                       sends a verification email, and returns a success message.
    """
    def post(self, request):
        """
        Resend the user registration verification email.

        Validates the incoming request data, retrieves the associated user, 
        and sends a new verification email to the user. If successful, 
        it returns a success response.

        Args:
            request (Request): The incoming HTTP request containing the user 
                               registration data.

        Returns:
            Response: A success message indicating that the verification email 
                      has been sent, along with an appropriate HTTP status code.
        """
        serializer = AdminUserResendRegistrationLinkSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_admin = serializer.validated_data['user']
        send_verification_email(user_admin)
        return Response({'status':'success','message':'User Registration Link has been sent.Please check your Email.'}, 
                        status=status.HTTP_201_CREATED)
    
# verify email of registered user
class AdminUserRegistrationEmailVerificationView(views.APIView):
    """
    Verify the user's email address during registration.

    This view handles GET requests to verify a user's email address
    by validating the provided token and user ID. It uses the 
    AdminUserRegistrationEmailVerifySerializer to check the token 
    and UID. If verification is successful, a success message is returned; 
    otherwise, an error message indicating an invalid or expired link is returned.

    Parameters:
        request (Request): The HTTP request containing the verification token and user ID.
        uidb64 (str): The base64 encoded user ID.
        token (str): The email verification token.

    Methods:
        get(request, uidb64, token): Validates the verification token and user ID, 
                                     and returns a success or error message based on 
                                     the result of the validation.
    """
    def get(self, request, uidb64, token):
        """
        Validate the email verification token and user ID.

        This method checks if the provided token and user ID are valid. 
        If the verification is successful, it returns a success response;
        otherwise, it returns an error response indicating that the 
        verification link is invalid or expired.

        Args:
            request (Request): The incoming HTTP request for email verification.
            uidb64 (str): The base64 encoded user ID.
            token (str): The email verification token.

        Returns:
            Response: A success message if verification is successful; 
                      an error message if the link is invalid or expired, 
                      along with an appropriate HTTP status code.
        """
         # Pass the RabbitMQ publishing function to the serializer context
        serializer = AdminUserRegistrationEmailVerifySerializer(data=request.data, context={'uid':uidb64, 'token':token, 'publish_to_rabbitmq': publish_to_rabbitmq})
        if serializer.is_valid(raise_exception=True):
            return Response({'status':'success','message':'Email verification successful. You can now log in.'},
                            status=status.HTTP_200_OK)
        return Response({'status':'error','message':'Invalid verification link or the link has expired.'}, 
                        status=status.HTTP_400_BAD_REQUEST)


class AdminUserSendLoginOTPView(views.APIView):
    """
    API view to send a One-Time Password (OTP) to an admin user's email.

    This view handles POST requests to authenticate an admin user and send an OTP
    to the registered email address if authentication is successful.

    Authentication:
        JWTAuthentication: Requires a valid JWT token to access this view.

    Renderer:
        UserRenderer: Custom renderer for formatting responses.

    Methods:
        post: Authenticates the user based on email and password, generates an OTP,
              and sends it to the user's email address.
    """
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]
    def post(self, request):
        """
        Handle POST requests to authenticate the user and send an OTP.

        This method validates the input data, authenticates the user using 
        email and password, generates a One-Time Password (OTP) if the 
        user is an admin, and sends the OTP to the user's registered email.

        Args:
            request (Request): The HTTP request object containing user credentials.

        Returns:
            Response: A DRF Response object indicating success or failure with status code.

        Raises:
            serializers.ValidationError: If input data is invalid.
        """
        serializer = AdminUserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email')
        print(f'email:{email}')
        password = serializer.validated_data.get('password')
        print(f'password:{password}')
        user_admin = User.objects.filter(email=email).first()
        organization = user_admin.userprofile.organization
        user = authenticate(email=email, password=password)
        print(f'user:{user}')
        if user:
            if not user.is_admin:
                return Response({'status': 'error', 'message': 'User is not an admin'}, status=status.HTTP_403_FORBIDDEN)
            # Ensure the user has an OTP secret key
            if not user_admin.otp_secret:
                user_admin.otp_secret = pyotp.random_base32() 
                user_admin.save() # Generate a new secret if not available
            # Generate OTP using user-specific secret
            totp = pyotp.TOTP(user_admin.otp_secret) 
            otp = totp.now()
            print(f'Generated OTP: {otp}')  # For debugging purposes, remove in production   
    
            #send email
            body = f'Your OTP code is {otp}'
            data = {
                'subject': 'Your OTP Code',
                'body':body,
                'to_email':user_admin.email,
            }
            Util.send_email(data)
            
            organization_data = {
                'id': organization.id,
                'name': organization.name,
            }
            
            # Publish OTP event to RabbitMQ
            publish_to_rabbitmq('platform_user_OTP', {
                'userId': user_admin.id,
                'email': user_admin.email,
                'organization': organization_data,
                'organizationId': organization.id if organization else None,
                'userType' : user_admin.userprofile.user_type,
                
            })
            
            
            return Response({'status': 'success', 'message': 'OTP sent to your email'}, status=status.HTTP_200_OK)

        else:
            return Response({'status': 'error', 'message': 'Invalid email or password'}, status=status.HTTP_404_NOT_FOUND)


class AdminUserVerifyLoginOTPView(views.APIView):
    """
    API view to verify the One-Time Password (OTP) for admin user login.

    This view handles POST requests to verify the OTP sent to an admin user's email.
    If the OTP is valid, it generates JWT tokens and sends them back in the response.
    Additionally, it publishes a login event to RabbitMQ for auditing or tracking purposes.

    Methods:
        post(request): Validates the provided OTP, verifies it, generates JWT tokens, 
                       and returns them in the response if successful.
    """

    def post(self, request):
        """
        Handle POST requests to verify the OTP for admin user login.

        This method fetches the user's OTP secret key, validates the input OTP,
        and checks if it matches the generated OTP using the TOTP algorithm. If
        the OTP is valid, JWT tokens are generated and returned in the response. 
        If the OTP is invalid, an error message is returned.

        Args:
            request (Request): The HTTP request object containing the OTP.

        Returns:
            Response: A DRF Response object indicating success or failure with status code.

        Raises:
            serializers.ValidationError: If input data is invalid.
        """
        # Fetch the user-specific secret key from the database
        user_admin = User.objects.filter(email=request.user.email).first()
        organization = user_admin.userprofile.organization
        serializer = AdminUserVerifyOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data.get('otp')
        print(f'received otp from request otp:{otp}') # For debugging purposes, remove in production
        # Verify OTP using the user-specific secret key
        totp = pyotp.TOTP(user_admin.otp_secret)
        if totp.verify(otp, valid_window=2):  # valid_window allows for time drift
            # Generate JWT tokens and respond with them
            token = get_tokens_for_user(request.user)
            
            organization_data = {
                'id': organization.id,
                'name': organization.name,
            }
            publish_to_rabbitmq('platform_user_login', {
                'userId': user_admin.id,
                'email': user_admin.email,
                'organization': organization_data,
                'organizationId': organization.id if organization else None,
                
                'userType' : user_admin.userprofile.user_type,
                
            })
            response = Response({'status': 'success', 'message': 'Login successful', 'token': token}, status=status.HTTP_200_OK)
            
            response.set_cookie(
                key='access_token',
                value=token['access'],
                httponly=True,
                secure=True,  # Use True in production
                samesite='Lax'  # Use 'Lax' or 'None' based on your requirement
            )
            
            response.set_cookie(
                key='refresh_token',
                value=token['refresh'],
                httponly=True,
                secure=True,  # Use True in production
                samesite='Lax'  # Use 'Lax' or 'None' based on your requirement
            )
            return response
        else:
                return Response({'status': 'error', 'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer
#adminUser Login   
class AdminUserLoginView(GenericAPIView):
    """
    Handle user login and JWT token management.

    This view handles POST requests to authenticate an admin user based on 
    their email and password. It clears any existing authentication cookies 
    and, upon successful authentication, generates new JWT tokens for the user. 
    These tokens are then set in cookies to manage user sessions.

    Authentication:
        JWTAuthentication: Used to verify the user's identity.

    Renderer:
        UserRenderer: Handles the rendering of responses.

    Methods:
        post(request): Authenticates the user, generates JWT tokens, sets them in cookies, 
                       and returns a response indicating success or failure.

    Parameters:
        request (Request): The HTTP request containing user credentials (email and password).

    Returns:
        Response: A response containing the JWT tokens if login is successful, 
                  or an error message if authentication fails.
    """
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer,BrowsableAPIRenderer]
    serializer_class = AdminUserLoginSerializer
    
    def get(self, request):
        serializer = self.get_serializer()
        return Response(serializer.data)
        
    def post(self, request):
        """
        Handle POST requests for admin user login.

        This method authenticates the user based on email and password,
        generates JWT tokens upon successful authentication, and sets
        these tokens in cookies. It also handles various error scenarios,
        such as user not found or inactive user.

        Args:
            request (Request): The HTTP request object containing user credentials.

        Returns:
            Response: A DRF Response object indicating success or failure with status code.
        """
        # Clear existing cookies
        response = Response()
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data.get('email')
       
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'status':'error', 'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)  
        userprofile = user.userprofile
        if not userprofile.is_active:
            return Response({'status':'error', 'message': 'User is not active. Please vefify the email'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            user = User.objects.get(email=email)
            password = serializer.validated_data.get('password')
            user_admin = authenticate(email=email, password=password)
            print(f'user : {user_admin}')
        if user_admin is not None:
            token = get_tokens_for_user(user_admin)
            response = Response({'status':'success', 'message':'User Login Successful', 'token':token,}, status=status.HTTP_200_OK)
            
            # Publish admin user login event to RabbitMQ
            publish_to_rabbitmq('platform_user_login', {
                'userId': user_admin.id,
                'email': user_admin.email,
                'organizationId':user_admin.userprofile.organization.id if user_admin.userprofile and user_admin.userprofile.organization else None,
                'userType' : user_admin.userprofile.user_type,
                
            })
             # Debug: Print cookies set
            print(f"Set Cookies - Access Token: {token['access']}, Refresh Token: {token['refresh']}")
        
            # Set the JWT tokens in cookies
            response.set_cookie(
                key='access_token',
                value=token['access'],
                httponly=False,
                secure=False, # Use True in production
                samesite='Lax', # Use 'Lax' or 'None' based on your requirement
                )
            
            response.set_cookie(
                key='refresh_token',
                value=token['refresh'],
                httponly=False,
                secure=False, # Use True in production
                samesite='None', # Use 'Lax' or 'None' based on your requirement
            )
            response["Access-Control-Allow-Origin"] = request.META.get("HTTP_ORIGIN")
            response["Access-Control-Allow-Credentials"] = "true"
            return response
        else:
            return Response({'status':'error', 'message':'Email or Password is not Valid'}, status=status.HTTP_400_BAD_REQUEST)
        


class CustomTokenRefreshView(TokenRefreshView):
    """
    Handle token refresh requests and manage JWT tokens.

    This view processes POST requests to refresh the JWT access token using a provided 
    refresh token. It validates the refresh token and, if valid, generates a new access 
    token and sets it in a secure HTTP-only cookie.

    Methods:
        post(request, *args, **kwargs): Validates the provided refresh token, generates 
                                        a new access token, and sets it in a cookie. 
                                        Returns a response with the new access token 
                                        or an error message if the refresh token is invalid 
                                        or missing.

    Parameters:
        request (Request): The HTTP request containing the refresh token.

    Returns:
        Response: A JSON response containing the new access token if successful, 
                  or an error message if the refresh token is invalid or missing.
    """
    def post(self, request, *args, **kwargs):
        """
        Handle POST requests for refreshing JWT access tokens.

        This method validates the provided refresh token and generates a new access 
        token if the refresh token is valid. The new access token is then set in a 
        secure HTTP-only cookie.

        Args:
            request (Request): The HTTP request object containing the refresh token.

        Returns:
            Response: A DRF Response object containing the new access token or 
                      an error message if the refresh token is invalid or missing.
        """
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'status':'error','message': 'Refresh Token not found'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Create serializer with the provided refresh token
        serializer = TokenRefreshSerializer(data={'refresh': refresh_token})
        
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            return Response({'status':'error', 'message':'Invalid or expired refresh token','data':e}, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract access token from validated data
        token = serializer.validated_data
        
        # Create response with access token
        response = JsonResponse({'access': token['access']})
        print(f'response: {response}')
        response.set_cookie(
            key='access_token',
            value=token['access'],
            secure=False,  # Use True in production
            httponly=True,
            samesite='Lax'  # Use 'Lax' or 'None' based on your requirement
        )
        return response
        
# adminUser Profile    
class AdminUserProfileView(views.APIView):
    """
    Retrieve and update user profiles.

    This view handles GET and PUT requests for managing user profiles. It requires 
    authentication and permission checks to ensure that only authorized users or admins 
    can access or modify the profile information.

    Methods:
        get(request, id=None): Retrieves the profile information of the currently authenticated 
                               user. Returns user details or an error message if the user is not found.

        put(request, id=None): Updates the profile information of the currently authenticated 
                               user with the provided data. Returns a success message and updated 
                               data if the update is successful, or validation errors if the update 
                               fails. 

    Parameters:
        request (Request): The HTTP request containing user profile data or the user ID.

    Returns:
        Response: A JSON response with user profile data or error messages, depending on 
                  the request method and outcome.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminOrSelf, IsOrganizationMember]
    renderer_classes = [UserRenderer]
    
    def get(self, request, id=None):
        """
        Handle GET requests for retrieving the user profile.

        Args:
            request (Request): The HTTP request object.
            id (int, optional): The user ID. Not used for fetching the authenticated user.

        Returns:
            Response: A response containing user profile data or an error message.
        """
        try:
            user = request.user
            serializer = AdminUserProfileSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'status':'error', 'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
    def put(self, request, id=None):
        """
        Handle PUT requests for updating the user profile.

        Args:
            request (Request): The HTTP request object containing user data.
            id (int, optional): The user ID. Not used for updating the authenticated user.

        Returns:
            Response: A response indicating success or failure of the update operation.
        """
        try:
            user_admin = request.user
            organization = request.user.userprofile.organization
            serializer = AdminUserProfileSerializer(user_admin, data=request.data, partial=True,context={'request': request})
            if serializer.is_valid():
                serializer.save()
                 # Prepare organization data for RabbitMQ message
                organization_data = {
                    'id': organization.id,
                    'name': organization.name,
            } if organization else None
                
                
                # Publish OTP event to RabbitMQ
                publish_to_rabbitmq('platform_user_updated', {
                    'userId': user_admin.id,
                    'email': user_admin.email,
                    'organization': organization_data,
                    'organizationId': organization.id if organization else None,
                    'userType' : user_admin.userprofile.user_type,
                
            })
                return Response({'status':'success', 'message': 'User updated successfully', 'data': serializer.data}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'status':'error', 'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        

#user_admin password change 
class AdminUserPasswordChangeView(views.APIView):
    """
    Change the password of the authenticated user.

    This view handles POST requests for changing the password of the currently authenticated user.
    It validates the provided password data and updates the user's password if the data is valid.

    Methods:
        post(request): Processes the password change request. Validates the provided data and 
                       updates the user's password if the data is valid. Returns a success 
                       message upon successful password change.

    Parameters:
        request (Request): The HTTP request containing the current and new password data.

    Returns:
        Response: A JSON response with a success message if the password is changed successfully, 
                  or validation errors if the provided data is invalid.
    """
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        """
        Handle POST requests to change the user's password.

        Args:
            request (Request): The HTTP request object containing the password data.

        Returns:
            Response: A response indicating success or failure of the password change operation.
        """
        user_admin = request.user
        organization= request.user.userprofile.organization
        serializer = AdminUserPasswordChangeSerializer(data=request.data, context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        
        # Prepare organization data for RabbitMQ message
        organization_data = {
            'id': organization.id,
            'name': organization.name,
    } if organization else None
        
        # Publish user admin password change event to RabbitMQ
        publish_to_rabbitmq('platform_user_password_change', {
            'userId': user_admin.id,
            'email': user_admin.email,
            'organization': organization_data,
            'organizationId': organization.id if organization else None,
            'userType' : user_admin.userprofile.user_type,
            
        })
        return Response({'status':'success', 'message':'Password Changed Successfully'}, status=status.HTTP_200_OK)   
    

# user_admin password reset via email    
class AdminUserPasswordResetEmailView(views.APIView):
    """
    Request a password reset email for the authenticated user.

    This view handles POST requests to send a password reset link to the email address of 
    the currently authenticated user. It validates the provided data and, upon successful 
    validation, sends a password reset link to the user's email.

    Methods:
        post(request): Processes the password reset request. Validates the provided data and 
                       sends a password reset link if the data is valid. Returns a success 
                       message indicating that the reset link has been sent.

    Parameters:
        request (Request): The HTTP request containing the necessary data to initiate the 
                           password reset process.

    Returns:
        Response: A JSON response with a status message indicating success and instructions 
                  to check the email for the password reset link.
    """
    # authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]
    # permission_classes = [IsAuthenticated]
    def post(self, request):
        """
        Handle POST requests to send a password reset link to the authenticated user's email.

        Args:
            request (Request): The HTTP request object containing user data.

        Returns:
            Response: A response indicating whether the email was sent successfully.
        """
        serializer = AdminUserPasswordResetEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'status':'success', 'message':'Password Reset Link has been sent.Please check your Email.'}, 
                        status=status.HTTP_200_OK) 
    
 
   
class AdminUserPasswordResetView(views.APIView):
    """
    View for handling password reset using a reset token and user ID.

    This view allows authenticated users to reset their password by providing a valid 
    reset token and user ID. The `GET` request must include these parameters to 
    validate and process the password reset.

    Methods:
        get(request, uid, token): Validates the reset token and user ID, then processes 
                                  the password reset. Returns a success message if the 
                                  password is changed successfully.

    Parameters:
        request (Request): The HTTP request containing the reset token and user ID.
        uid (str): URL-safe base64-encoded user ID.
        token (str): Password reset token.

    Returns:
        Response: A JSON response indicating the success of the password reset.
    """
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]
    # permission_classes = [IsAuthenticated]
    def get(self, request, uid, token):
        """
        Handle GET requests to reset the user's password.

        Validates the reset token and user ID, then resets the password if valid.

        Args:
            request (Request): The HTTP request object.
            uid (str): URL-safe base64-encoded user ID.
            token (str): Password reset token.

        Returns:
            Response: A response indicating the success of the password reset.
        """
        user_admin = request.user
        organization = request.user.userprofile.organization
        serializer = AdminUserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
        serializer.is_valid(raise_exception=True)
        
        # Prepare organization data for RabbitMQ message
        organization_data = {
            'id': organization.id,
            'name': organization.name,
    } if organization else None
        
        # Publish password reset event to RabbitMQ
        publish_to_rabbitmq('platform_user_password_reset', {
            'userId': user_admin.id,
            'email': user_admin.email,
            'organization': organization_data,
            'organizationId': organization.id if organization else None,
            'userType' : user_admin.userprofile.user_type,
                
            })
        return Response({'status':'success', 'message':'Password Changed Successfully'}, status=status.HTTP_200_OK)
    
        
class UserLogoutView(views.APIView):
    """
    View to handle the logout process for an authenticated admin user.

    This view uses JWT authentication to ensure the user is logged in and has valid tokens.
    Upon receiving a POST request, the user is logged out, and the access and refresh tokens
    are deleted from the cookies.

    Authentication:
        - JWTAuthentication: Validates the JWT tokens.
        - IsAuthenticated: Ensures the user is authenticated.

    Rendering:
        - UserRenderer: Custom renderer for the response.

    Methods:
        - post: Logs out the user and deletes the JWT tokens from the cookies.
    """
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Handle POST requests to log out the user.

        Logs out the authenticated user and deletes the JWT access and refresh tokens
        from the cookies.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response indicating the logout was successful, with the
                      JWT cookies deleted.
        """
        
        # Log out the user
        user_admin = request.user
        organization = request.user.userprofile.organization
        logout(request)
        
        organization_data = {
            'id': organization.id,
            'name': organization.name,
        }
        # Publish useradmin loggedout event to RabbitMQ
        publish_to_rabbitmq('platform_user_logged_out', {
            'userId': user_admin.id,
            'email': user_admin.email,
            'organization': organization_data,
            'organizationId': organization.id if organization else None,
            'userType' : user_admin.userprofile.user_type,
            
        })

        # Create a response to delete the cookies
        response = Response({'status':'success', 'message':'Logout successful'}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response
    
    
    
    
    
    
    
          
           