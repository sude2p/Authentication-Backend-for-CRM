from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'org-user-profile', views.OrgUserProfileModelViewSet, basename='org-user-profile')
router.register(r'org-user-profile-update', views.OrgUserUpdateUserProfileDetailsModelViewSet, basename='org-user-profile-update')

urlpatterns = [
    path('', include(router.urls)),
    path('organization-create/',views.OrganizationCreateView.as_view(), name="organization-create"),
    path('organization-profile/',views.OrganizationProfileView.as_view(), name="organization-profile"),
    path('organization-profile/<int:id>/',views.OrganizationProfileView.as_view(), name="organization-profile"),
    path('invite-org-users/', views.OrgUserInviteEmailAPIView.as_view(), name='invite-org-users'),
    
    
    path('org-user-import/',views.ImportOrgUserView.as_view(), name="import-org-user"),
    
    path('org-user-email-password-verify/<uid>/<token>/',views.OrgUserEmailVerifyView.as_view(), name="org-user-email-password-verify"),
    path('org-user/login/',views.OrgUserLoginAPIView.as_view(), name="org-user-login"),
    path('org-user/password-change/',views.OrgUserPasswordChangeAPIView.as_view(), name="password-change"),
    path('org-user-update/<int:pk>/',views.OrgUserUpdateByAdminAPIView.as_view(), name="org-user-update-by-admin"),
    path('org-user/user-profile-fields-check/',views.UserProfileFieldsCheckAPIView.as_view(), name="user-profile-fields-check"),
    
    


]
