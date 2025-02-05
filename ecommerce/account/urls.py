from django.urls import path
from .views import *

urlpatterns = [
    path('registration/', AccountView.as_view(), name='register-user'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-otp-to-verify-email/', ResendOtpToVerifyEmailView.as_view(), name='resend-verify-email-otp'),
    path('login/', UserLoginView.as_view(), name='login-user'),
    path('logout/', UserLogoutView.as_view(), name='logout-user'),
    path('update-password/', UserUpdatePasswordView.as_view(), name='update-password'),
    path('send-otp-to-reset-password/', SendOtpToResetPasswordView.as_view(), name='send-otp-to-reset-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('admin/update-password/<int:id>/', UserUpdatePasswordByAdminView.as_view(), name='admin-update-password'),
    path('admin/user-profile/<int:id>/', UserProfileViewByAdmin.as_view(), name='admin-user-profile'),
    path('user-profile/', UserProfileView.as_view(), name='user-profile'),
]
