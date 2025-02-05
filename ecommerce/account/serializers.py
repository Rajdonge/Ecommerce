from rest_framework import serializers
from .models import MyUser

# User Logout Serializer imports
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

# User Account Serializer
class AccountSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = MyUser
        fields = ['email', 'password', 'password2', 'full_name', 'date_of_birth', 'gender', 'mobile', 'address']
        
        extra_kwargs = {
            'password': {'write_only': True}
        }
    def validate(self, attrs):
        # Check email
        email = attrs.get('email')
        if MyUser.objects.filter(email=email).exists():
            raise serializers.ValidationError({'email': 'Email is already in use'})
        
        # Check password
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError({'password': 'Password must match'})
        return attrs
    
    def create(self, validated_data):
        return MyUser.objects.create_user(**validated_data)
    
# Verify Email Serializer
class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    verify_email_otp = serializers.CharField()
    
# Resend Verify Email OTP Serializer
class ResendOtpToVerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


# User Login Serializer
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


# User Logout Serializer
class UserLogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is invalid or expired')
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh')
        return attrs
    
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            raise serializers.ValidationError({'refresh': self.error_messages['bad_token']})
        
# User Update Password Serializer
class UserUpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=255, write_only=True)   
    new_password = serializers.CharField(max_length=255, write_only=True)
    confirm_password = serializers.CharField(max_length=255, write_only=True)

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        user = self.context.get('user')

        # Check if old password is correct
        if not user.check_password(old_password):
            raise serializers.ValidationError({'old_password': 'Old password is incorrect'})
        
        # Check if new password and confirm password match
        if new_password != confirm_password:
            raise serializers.ValidationError({'new_password': 'Passwords must match'})
        return attrs
    
    def save(self, **kwargs):
        user = self.context.get('user')
        new_password = self.validated_data.get('new_password')
        user.set_password(new_password) # Hash the new password
        user.save()
        return user
    
# User Update Password By Admin Serializer
class UserUpdatePasswordByAdminSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=255, write_only=True)
    confirm_password = serializers.CharField(max_length=255, write_only=True)

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        user = self.context.get('user')

        # Check if new password and confirm password match
        if new_password != confirm_password:
            raise serializers.ValidationError({'new_password': 'Passwords must match'})
        return attrs
    
    def save(self, **kwargs):
        user = self.context.get('user')
        new_password = self.validated_data.get('new_password')
        user.set_password(new_password) # Hash the new password
        user.save()
        return user
    
# Send Otp to Reset Password Serializer
class SendOtpToResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

# Reset Password Serializer
class ResetPasswordSerializer(serializers.Serializer):
    reset_password_otp = serializers.CharField()
    new_password = serializers.CharField(max_length=255, write_only=True)
    confirm_password = serializers.CharField(max_length=255, write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({'new password': 'Password must match.'})
        
        user = MyUser.objects.filter(reset_password_otp=attrs['reset_password_otp']).first()
        if not user:
            raise serializers.ValidationError({'reset_password_otp': 'Invalid OTP'})

        self.context['user'] = user
        return attrs
    
    def save(self, **kwargs):
        user = self.context.get('user')
        new_password = self.validated_data.get('new_password')
        user.set_password(new_password) # Hash the new password
        user.reset_password_otp = None # Clear OTP after reset
        user.save()