
from django.urls import path, include
from core import views

urlpatterns = [
    path('userAdmin-register/',views.AdminUserRegistrationView.as_view(), name="user-admin-register"),
    path('userAdmin-registrationlink-resend/',views.AdminUserRegistrationLinkResendView.as_view(), name="userAdmin-registrationlink-resend"),
    path('userAdmin-verify-email/<uidb64>/<token>/', views.AdminUserRegistrationEmailVerificationView.as_view(), name='userAdmin-verify-email'),
    path('userAdmin-send-otp-login/',views.AdminUserSendLoginOTPView.as_view(), name="userAdmin-send-otp-login"),
    path('userAdmin-verify-otp-login/',views.AdminUserVerifyLoginOTPView.as_view(), name="userAdmin-verify-otp-login"),
    path('userAdmin-login/',views.AdminUserLoginView.as_view(), name="userAdmin-login"),
    path('userAdmin-profile/',views.AdminUserProfileView.as_view(), name="userAdmin-profile"),
    path('userAdmin-profile/<int:id>/',views.AdminUserProfileView.as_view(), name="userAdmin-profile"),
    path('userAdmin-password-change/',views.AdminUserPasswordChangeView.as_view(), name="userAdmin-password-change"),
    path('userAdmin-password-reset-email/', views.AdminUserPasswordResetEmailView.as_view(), name="userAdmin-password-reset"),
    path('userAdmin-password-reset/<uid>/<token>/', views.AdminUserPasswordResetView.as_view(), name="userAdmin-password-reset"),
    path('token-refresh/', views.CustomTokenRefreshView.as_view(), name='token-refresh'),
    
    path('user-get/<int:pk>/',views.get_user, name="user-get"),
    path('user-logout/',views.UserLogoutView.as_view(), name="user-logout"),
    
    
    
    
    
    
]
