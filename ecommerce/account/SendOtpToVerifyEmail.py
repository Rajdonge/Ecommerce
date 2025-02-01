from django.core.mail import send_mail
import random
from django.conf import settings
from .models import MyUser

def Send_Otp_Via_Email(email):
    verify_email_otp = random.randint(1000, 9999)
    subject = 'Verify your email'
    message = f'Your OTP is {verify_email_otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)
    user_obj = MyUser.objects.get(email=email)
    user_obj.verify_email_otp = verify_email_otp
    user_obj.save()
    return verify_email_otp