from rest_framework import serializers
from .models import MyUser

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
        if MyUser.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError({'email': 'Email is already in use'})
        
        # Check password
        password = attrs['password']
        password2 = attrs['password2']

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