import io
import csv
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from django.contrib.auth import authenticate
from core.views import get_tokens_for_user
from rest_framework import views
from core.renderer import UserRenderer
from rest_framework.permissions import IsAuthenticated
from core.permissions import IsAdminUserAndOwner, IsAdminOrSelf, IsOrganizationMember
from .serializers import (
    ImportOrgUserSerializer,
    OrgUserInviteEmailSerializer,
    OrgUserListSerializer,
    OrgUserSerializer,
    OrgUserEmailRegistrationVerificationSerializer,
    OrgUserUpdateSerializer,
    OrganizanizationCreateSerializer,
    OrganizationProfleSerializer,
    OrgUserLoginSerializer,
    OrgUserPasswordChangeSerializer,
    OrgUserUpdateUserSerializer,
    UserProfileFieldCheckSerializer,
   
)
from rest_framework.pagination import PageNumberPagination
from core.publisher import publish_to_rabbitmq
from rest_framework.response import Response
from rest_framework import status
from core.models import User, UserProfile
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import viewsets
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from .models import Organization


# Create your views here.


class OrganizationCreateView(views.APIView):
    """
    API view for creating an Organization instance.

    - Renderer: Uses UserRenderer for rendering responses.
    - Permissions: Requires authentication and admin access (or self).
    - POST method:
        - Validates and saves the organization data using OrganizanizationCreateSerializer.
        - Triggers a 'organization_created' event with RabbitMQ.
        - Returns a success response with status code 201 if creation is successful.
        - Returns a 403 Forbidden response if the user is not an admin.
    """

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated, IsAdminOrSelf]

    def post(self, request):
        if request.user.is_admin:
            user_admin = request.user
            serializer = OrganizanizationCreateSerializer(
                data=request.data, context={"user": user_admin}
            )
            serializer.is_valid(raise_exception=True)
            organization = serializer.save()

            # organization created event firing

            publish_to_rabbitmq(
                "organization_created",
                {
                    "userId": user_admin.id,
                    "orgId": organization.id,
                    "createdBy": user_admin.id,
                    "email": organization.email,
                    "name": organization.name,
                },
            )
            return Response(
                {
                    "status": "success",
                    "message": "Organization Created Successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_201_CREATED,
            )

        else:
            return Response(
                {"status": "error", "message": "Invalid User"},
                status=status.HTTP_403_FORBIDDEN,
            )


class OrganizationProfileView(views.APIView):
    """
    API view for retrieving, updating, and deleting the organization profile of the authenticated user.

    - Renderer: Utilizes `UserRenderer` for rendering responses.
    - Permissions: Requires authentication and grants access based on the user's admin status or self.

    Methods:
        get(request, id=None):
            Retrieves the organization profile associated with the authenticated user.
            Returns a 200 OK response with the organization data or a 404 error if the user profile is not found.

        put(request, id=None):
            Updates the organization profile of the authenticated user.
            Requires partial data. Returns a 200 OK response if the update is successful, 
            or a 400 error with validation errors if the update fails.

        delete(request, id=None):
            Deletes the organization profile of the authenticated user.
            Returns a 200 OK response if the deletion is successful, 
            or a 404 error if the organization or user profile is not found.
    """

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated, IsAdminOrSelf]

    def get(self, request, id=None):
        """
        Retrieves the organization profile for the authenticated user.

        If an organization ID is provided, it fetches the specific organization profile.
        If no ID is provided, it returns all organizations associated with the user.

        Args:
            request (Request): The HTTP request object.
            id (int, optional): The ID of the organization to retrieve.

        Returns:
            Response: A response object containing the status, message, and organization data.
            - 200 OK: Successful retrieval of organization data.
            - 404 Not Found: If the organization does not exist.
        """
        # fetch token from Authorization header
        try:
            created_by= request.user
            if id:
            # user_profile = UserProfile.objects.get(user=user)
                organization = Organization.objects.get(created_by=created_by, id=id)
                serializer = OrganizationProfleSerializer(organization)
                return Response(
                    {
                        "status": "success",
                        "message": "Organization fetched successfully",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            if not id:
                organization = Organization.objects.filter(created_by=created_by)   
                serializer = OrganizationProfleSerializer(organization, many=True)
                return Response(
                    {
                        "status": "success",
                        "message": "Organization fetched successfully",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
                
        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "Organization not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
            

    def put(self, request, id=None):
        """
        Updates the organization profile of the authenticated user.

        Args:
            request (Request): The HTTP request object containing the update data.
            id (int, optional): The ID of the organization to update.

        Returns:
            Response: A response object indicating the status of the update operation.
            - 200 OK: Successful update of the organization profile.
            - 400 Bad Request: If the update fails due to validation errors.
            - 404 Not Found: If the organization or user profile does not exist.
        """

        try:
            user_admin = request.user
            user_profile = UserProfile.objects.get(user=user_admin)
            organization = user_profile.organization
            serializer = OrganizationProfleSerializer(
                organization, request.data, partial=True
            )
            if serializer.is_valid():
                serializer.save()
                publish_to_rabbitmq(
                    "organization_updated",
                    {
                        "userId": user_admin.id,
                        "orgId": organization.id,
                        "createdBy": user_admin.id,
                        "email": organization.email,
                        "name": organization.name,
                    },
                )
                return Response(
                    {
                        "status": "success",
                        "message": "User updated successfully",
                        "data": serializer.data,
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"status": "error", "message": "errors", "data": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except User.DoesNotExist:
            return Response(
                {"status": "errror", "message": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
    def delete(self, request, id=None):
        """
        Deletes the organization profile of the authenticated user.

        Args:
            request (Request): The HTTP request object.
            id (int, optional): The ID of the organization to delete.

        Returns:
            Response: A response object indicating the status of the delete operation.
            - 200 OK: Successful deletion of the organization profile.
            - 404 Not Found: If the organization or user profile does not exist.
        """
        try:
            user_admin = request.user
            user_profile = UserProfile.objects.get(user=user_admin)
            organization = user_profile.organization
            organization.delete()
            publish_to_rabbitmq("organization_deleted",
                                
                                {
                    "userId": user_admin.id,
                    "orgId": organization.id,
                    "createdBy": user_admin.id,
                    "email": organization.email,
                    "name": organization.name,
                }),
            return Response(
                {"status": "success", "message": "User deleted successfully"},
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        
            

class OrgUserProfileModelViewSet(viewsets.ModelViewSet):
    """
    API view set for managing organization user profiles.

    This view set provides CRUD operations for organization user profiles and allows for filtering,
    searching, and ordering of results.

    Attributes:
        queryset (QuerySet): The default queryset for the view set.
        serializer_class (Serializer): The serializer class used for the view set.
        pagination_class (Type[Pagination]): The pagination class for paginating results.
        renderer_classes (list): The list of renderer classes for rendering responses.
        permission_classes (list): The list of permission classes for access control.
        filter_backends (list): The filter backends for filtering, searching, and ordering.
        filterset_fields (list): The fields available for filtering the queryset.
        search_fields (list): The fields available for searching the queryset.
    """

    queryset = User.objects.all()
    serializer_class = OrgUserSerializer
    pagination_class = PageNumberPagination
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated, IsAdminUserAndOwner,IsOrganizationMember]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_fields = [
        
        "userprofile__is_active",
        
        "userprofile__organization",
        "userprofile__user_type",
        "userprofile__contact_number",
        "user__first_name",
        "user__last_name",
        "user__email",
    ]
    search_fields = ["user__first_name", "user__last_name", "user__email"]
    ordering_fields = ["user__first_name", "user__last_name", "user__email"]
    ordering = ["user__first_name", "user__last_name", "user__email"]
    
    

    def create(self, request, *args, **kwargs):
        """
        Creates a new organization user profile.

        This method expects the organization ID in the request headers and the user's role in the request body.
        If the user is created successfully, an event is published to RabbitMQ.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response object indicating the status of the create operation.
            - 201 Created: Successfully created organization user profile.
            - 400 Bad Request: If the request data is invalid.
        """
        organization_id = request.headers.get("Organization")
        
        role = request.data.get("role")
        
          
        
        serializer = self.get_serializer(
            data=request.data, context={"user": request.user,"organization_id": organization_id, "role": role}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        

        publish_to_rabbitmq(
            "org_user_created",
            {
                "userId": user.id,
                "email": user.email,
                "firstName": user.first_name,
                "lastName": user.last_name,
                "role": role,
                "isAdmin": user.is_admin,
                "isStaff": user.is_staff,
                "contactNumber": user.userprofile.contact_number,
                "organizationId": user.userprofile.organization.id if user.userprofile.organization else None,
                "userType": user.userprofile.user_type,
                "createdBy": user.userprofile.created_by.user.id,
            },
        ),
        return Response(
            {
                "status": "success",
                "message": "Org User created successfully",
                "data": serializer.data,
            },
            status=status.HTTP_201_CREATED,
        )

    def list(
        self, request, *args, **kwargs
    ):  
        """
        Retrieves a list of organization user profiles created by the authenticated user.

        The list is filtered based on the user's profile and can include pagination, filtering, and sorting.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response object containing the list of organization user profiles.
            - 200 OK: Successfully retrieved the list of organization user profiles.
        """

        queryset = self.filter_queryset(UserProfile.objects.filter(created_by = request.user.userprofile))
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = OrgUserListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = OrgUserListSerializer(queryset, many=True)
        return Response(
            {"status": "success", "message": "Org User List", "data": serializer.data},
            status=status.HTTP_200_OK,
        )

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieves a specific organization user profile.

        This method fetches the user profile associated with the given ID.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response object containing the organization user profile data.
            - 200 OK: Successfully retrieved the organization user profile.
            - 404 Not Found: If the user profile does not exist.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
            {
                "status": "success",
                "message": "Org User retrieved successfully",
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        """
        Deletes a specific organization user profile.

        This method removes the user profile associated with the given ID and publishes a deletion event
        to RabbitMQ.

        Args:
            request (Request): The HTTP request object.

        Returns:
            Response: A response object indicating the status of the delete operation.
            - 204 No Content: Successfully deleted the organization user profile.
            - 404 Not Found: If the user profile does not exist.
        """
        
        # Access the user associated with the UserProfile instance
        
        
        try:
            instance = self.get_object()
            user = instance
            email = user.email
        except User.DoesNotExist:
            return Response(
                {"status": "error", "message": "User not found for this profile."},
                status=status.HTTP_404_NOT_FOUND,
            )
        
        self.perform_destroy(user)
        publish_to_rabbitmq(
            "org_user_deleted",
            {
                "userId": user.id,
                "email": email
                
            },
        )
        return Response(
            {"status": "success", "message": "Org User deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )


class OrgUserUpdateByAdminAPIView(RetrieveUpdateAPIView):
    """
    API view for updating organization user profiles by an admin user.

    This view allows an authenticated admin user to update the details of
    organization user profiles. It ensures that the user making the request
    has the necessary permissions to perform the update.

    Attributes:
        serializer_class (Serializer): The serializer class used for the view.
        queryset (QuerySet): The default queryset for the view.
        lookup_field (str): The field used to look up the object for retrieval.
        permission_classes (list): The list of permission classes for access control.
    """

    serializer_class  = OrgUserUpdateSerializer
    queryset = User.objects.all()
    lookup_field = "pk"
    permission_classes = [IsAuthenticated, IsAdminUserAndOwner, IsOrganizationMember]
    
    def update(self, request, *args, **kwargs):
        """
        Updates an existing organization user profile.

        This method validates the incoming data against the serializer, and if
        valid, updates the user profile with the new information. It returns
        a success response if the update is successful, or an error response if
        the data is invalid.

        Args:
            request (Request): The HTTP request object containing the update data.
            kwargs (dict): Additional keyword arguments, including 'partial' to
                indicate whether the update should be partial.

        Returns:
            Response: A response object indicating the status of the update operation.
            - 200 OK: Successfully updated the organization user profile.
            - 400 Bad Request: If the provided data is invalid.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)
            response = Response(
                {
                    "status": "success",
                    "message": "Org User updated successfully",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )
        else:
            response = Response(
                {
                    "status": "fail",
                    "message": "Invalid data",
                    "errors": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return response





class OrgUserEmailVerifyView(views.APIView):
    def get(self, request, uid, token):
        try:
            uid = force_str(urlsafe_base64_decode(uid))
            print(f"user_id: {uid}")  #
            print(f"token: {token}")  # for debugging
            org_user = User.objects.get(id=uid)
            print(f"org_user: {org_user}")  # for debugging
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"status": "error", "message": "Invalid token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if default_token_generator.check_token(org_user, token):

            return Response(
                {"status": "success", "message": "Link verified successfully."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "error", "message": "Invalid token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def post(self, request, uid, token):
        serializer = OrgUserEmailRegistrationVerificationSerializer(
            data=request.data, context={"uid": uid, "token": token}
        )
        if serializer.is_valid(raise_exception=True):
            token = serializer.save()
            response = Response(
                {
                    "status": "success",
                    "message": "Password set successfully.",
                    "token": token,
                },
                status=status.HTTP_200_OK,
            )
            # Set cookies for JWT tokens
            response.set_cookie(
                key="access_token",
                value=token["access"],
                httponly=True,
                secure=False,
                samesite="None",
            )
            response.set_cookie(
                key="refresh_token",
                value=token["refresh"],
                httponly=True,
                secure=False,
                samesite="None",
            )

            # Optionally publish the login event
            publish_to_rabbitmq(
                "Org_user_login",
                {
                    "userId": serializer.validated_data["org_user"].id,
                    "email": serializer.validated_data["org_user"].email,
                },
            )

            return response


class OrgUserInviteEmailAPIView(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated, IsAdminUserAndOwner, IsOrganizationMember]
    serializer_class = OrgUserInviteEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            invites = serializer.save()
            
            publish_to_rabbitmq("org_user_invite_email", {"invites": invites})

            return Response(
                {"status": "success", "message": "Invites sent successfully"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrgUserLoginAPIView(views.APIView):
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]

    def post(self, request):
        # Clear existing cookies
        response = Response()
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        serializer = OrgUserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data.get("email")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'status':'error', 'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)  
        userprofile = user.userprofile
        if not userprofile.is_active:
            return Response({'status':'error', 'message': 'User is not active. Please vefify the email'}, status=status.HTTP_400_BAD_REQUEST)
        
        else:
            user = User.objects.get(email=email)
            password = serializer.validated_data.get("password")
            org_user = authenticate(email=email, password=password)
            print(f"org user : {org_user}")
        if org_user is not None:
            # Update user attributes
            org_user.is_active = True
            org_user.is_verified = True
            org_user.save()
            token = get_tokens_for_user(org_user)
            # Serialize the full user instance to include organization info
            user_data = OrgUserLoginSerializer(org_user).data
            response = Response(
                {
                    "status": "success",
                    "message": "User Login Successful",
                    "data": user_data,
                    "token": token,
                },
                status=status.HTTP_200_OK,
            )

            # publish org_user login event
            publish_to_rabbitmq(
                "org_user_login",
                {
                    "userId": org_user.id,
                    "email": org_user.email,
                },
            )
            # Debug: Print cookies set
            print(
                f"Set Cookies - Access Token: {token['access']}, Refresh Token: {token['refresh']}"
            )  # for debug

            # Set the JWT tokens in cookies
            response.set_cookie(
                key="access_token",
                value=token["access"],
                httponly=True,
                secure=False,  # Use True in production
                samesite="None",  # Use 'Lax' or 'None' based on your requirement
            )

            response.set_cookie(
                key="refresh_token",
                value=token["refresh"],
                httponly=True,
                secure=False,  # Use True in production
                samesite="None",  # Use 'Lax' or 'None' based on your requirement
            )
            return response
        else:
            return Response(
                {"status": "error", "message": "Email or Password is not Valid"},
                status=status.HTTP_404_NOT_FOUND,
            )




class ImportOrgUserView(GenericAPIView):
    
    serializer_class = ImportOrgUserSerializer

    permission_classes = [IsAdminUserAndOwner, IsAuthenticated, IsOrganizationMember]

    def post(self, request, *args, **kwargs):
        # Validate the uploaded file
        
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                 organization_id = request.headers.get("Organization")
                 print(organization_id)
            except Exception as exc:
                print("Error: ", str(exc))
            
            try:
                organization = Organization.objects.get(id=organization_id)
            except Exception as exc:
                return Response(
                    {"status": "error", "message": str(exc)},
                    status=status.HTTP_400_BAD_REQUEST,
                )       
            
                     
            
            # Read the uploaded CSV file
            csv_file = request.FILES["file"]
            data_set = csv_file.read().decode("UTF-8")
            io_string = io.StringIO(data_set)
            reader = csv.reader(io_string, delimiter=",", quotechar='"')
            # Skip the header if it exists
            next(reader)
            for col in reader:

                try:
                    new_user = User.objects.create(
                        email=col[0],
                        first_name=col[1],
                        last_name=col[2],
                    )
                    UserProfile.objects.create(
                        user=new_user,
                        contact_number=col[3],
                        created_by=request.user.userprofile,
                        organization=organization,
                    )
                    # email_list.append(new_user.email)
                    OrgUserSerializer.send_email_invite(new_user)
                except Exception as exc:
                    print("Error: ", str(exc), "in row")
                    continue
            return Response(
                {"status": "CSV imported successfully"}, status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OrgUserPasswordChangeAPIView(views.APIView):
    authentication_classes = [JWTAuthentication]
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        orguser = request.user
        print(f"orguser: {orguser}")

        serializer = OrgUserPasswordChangeSerializer(
            data=request.data, context={"orguser": orguser, "request": request}
        )
        serializer.is_valid(raise_exception=True)
        publish_to_rabbitmq(
            "org_user_password_changed",
            {"userId": orguser.id, "email": orguser.email},
        )
        return Response(
            {"status": "success", "message": "Password Changed Successfully"},
            status=status.HTTP_200_OK,
        )
        

class OrgUserUpdateUserProfileDetailsModelViewSet(viewsets.ModelViewSet):
   
    permission_classes = [IsAuthenticated, IsAdminUserAndOwner, IsOrganizationMember]
    renderer_classes = [UserRenderer]
    queryset = User.objects.all()
    serializer_class = OrgUserUpdateUserSerializer
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance == request.user:
            serializer = self.get_serializer(instance, data=request.data, partial=True)  
            
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            publish_to_rabbitmq(
                "org_user_profile_updated",
                {"userId": instance.id, "email": instance.email},
            )
            return Response({"status": "success", "message":"Org User updated successfully","data": serializer.data}, status=status.HTTP_200_OK) 
        else:
            return Response({"status": "fail", "message": "Invalid User"}, status=status.HTTP_403_FORBIDDEN)
        
        
class UserProfileFieldsCheckAPIView(GenericAPIView):
    renderer_classes =  [UserRenderer]
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileFieldCheckSerializer
    def get(self, request):
        user = request.user
        userprofile = user.userprofile
        try:
            if user.first_name or user.last_name is None:
                return Response({"status": "fail", "message": "First Name or Last Name is missing"}, status=status.HTTP_400_BAD_REQUEST)
            if userprofile.contact_number is None:
                return Response({"status": "fail", "message": "Contact Number is missing"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"status": "fail", "message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
               