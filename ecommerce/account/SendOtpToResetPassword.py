from django.core.mail import send_mail
import random
from django.conf import settings
from .models import MyUser

def Send_Otp_To_Reset_Password(email):
    reset_password_otp = random.randint(1000, 9999)
    subject = 'OTP to Reset Password'
    message = f'Your OTP is {reset_password_otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)
    user_obj = MyUser.objects.get(email=email)
    user_obj.reset_password_otp = reset_password_otp
    user_obj.save()
    return reset_password_otp