from django.urls import path
from .views import *

urlpatterns = [
    path('registration/', AccountView.as_view(), name='register-user'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-otp-to-verify-email/', ResendOtpToVerifyEmailView.as_view(), name='resend-verify-email-otp'),
]
