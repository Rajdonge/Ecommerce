from rest_framework.views import APIView
from .models import MyUser
from .serializers import AccountSerializer, ResendOtpToVerifyEmailSerializer, UserLoginSerializer, UserLogoutSerializer, UserUpdatePasswordSerializer, UserUpdatePasswordByAdminSerializer, SendOtpToResetPasswordSerializer, ResetPasswordSerializer, VerifyEmailSerializer
from rest_framework.response import Response
from rest_framework import status

# User Registration imports
from .SendOtpToVerifyEmail import *

# User Login imports
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken

# Reset Password imports
from .SendOtpToResetPassword import *

# Update Password by Admin imports
from rest_framework.permissions import IsAdminUser

# User Profile imports
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

# User Profile View by admin
from django.http import Http404


# User Registration View
class AccountView(APIView):
    def post(self, request):
        users_data = request.data
        serializer = AccountSerializer(data=users_data)
        if serializer.is_valid():
            serializer.save()
            Send_Otp_Via_Email(serializer.data['email'])
            output = {'message':'User registered successfully. Please verify your email','data': serializer.data}
            return Response(output, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# Verify Email View
class VerifyEmailView(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = VerifyEmailSerializer(data=data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data.get('email').lower().strip()
                verify_email_otp = serializer.validated_data.get('verify_email_otp')

                user = MyUser.objects.filter(email=email)

                # Check if user exists
                if not user.exists():
                    return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
                # Check if user is already verified
                if user[0].is_verified:
                    return Response({'message': 'Email already verified'}, status=status.HTTP_400_BAD_REQUEST)

                if user[0].verify_email_otp != verify_email_otp:
                    return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
                user = user.first()
                user.is_verified = True
                user.save()
                return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            print('Internal server error', e)
            output_error = {'message': 'Internal server error', 'error':serializer.errors}
            return Response(output_error, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# Resend Verify Email OTP View
class ResendOtpToVerifyEmailView(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = ResendOtpToVerifyEmailSerializer(data=data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.validated_data.get('email').lower().strip()
                user = MyUser.objects.filter(email=email)
                if not user.exists():
                    return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
                if user[0].is_verified:
                    return Response({'message': 'Email already verified'}, status=status.HTTP_400_BAD_REQUEST)
                Send_Otp_Via_Email(email)
                return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            print('Internal server error', e)
            output_error = {'message': 'Internal server error', 'error':serializer.errors}
            return Response(output_error, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

        
# Function to generate Token
def generate_token(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# User Login View
class UserLoginView(APIView):
    def post(self, request):
        try:
            data = request.data
            serializer = UserLoginSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data['email'].lower().strip()
            password = serializer.validated_data['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                token = generate_token(user)
                update_last_login(None, user)
                user_data = MyUser.objects.filter(email=email).values().first()
                return Response({'message': 'Login successful', 'data': user_data, 'token': token}, status=status.HTTP_200_OK)
            return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print('Internal server error', e)
            return Response({'message': 'Internal server error', 'error': serializer.errors}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# User Logout View
class UserLogoutView(APIView):
    serializer_class = UserLogoutSerializer
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
    
# Update Password View
class UserUpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        data = request.data
        serializer = UserUpdatePasswordSerializer(data=data, context={'user': user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'message': 'Password updated successfully'}, status=status.HTTP_200_OK)    
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Update User Password by Admin View
class UserUpdatePasswordByAdminView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    def post(self, request, id):
        user = get_object_or_404(get_user_model(), id=id)
        data = request.data
        serializer = UserUpdatePasswordByAdminSerializer(data=data, context={'user': user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'message': 'Password updated successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# Send OTP to Reset Password View
class SendOtpToResetPasswordView(APIView):
    def post(self, request):
        data = request.data
        serializer = SendOtpToResetPasswordSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get('email').lower().strip()
        Send_Otp_To_Reset_Password(email)
        return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
    
# Reset Password View
class ResetPasswordView(APIView):
    def post(self, request):
        data = request.data
        serializer = ResetPasswordSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'Password reset successfully.'}, status=status.HTTP_200_OK)


# User Profile View by Admin
class UserProfileViewByAdmin(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    def get(self, request, id):
        try:
            user = get_object_or_404(get_user_model(), id=id)
            serializer = AccountSerializer(user)
            response_data = {
                'data': serializer.data,
                'message': f'User profile of {user.id} fetched successfully'
        }
            return Response(response_data, status=status.HTTP_200_OK)
        except Http404:
            return Response(
                {'error': 'User not found. Please check the ID and try again.'},
                status=status.HTTP_404_NOT_FOUND
                )
            
    
    def patch(self, request, id):
        user = get_object_or_404(get_user_model(), id=id)
        serializer = AccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            response_data = {
                'data': serializer.data,
                'message': f'User profile of {user.id} updated successfully'
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, id):
        user = get_object_or_404(get_user_model(), id=id)
        user.delete()
        return Response({'message': f'User id deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
# User Profile View
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, id=None):
        # Ensure the user can only fetch their own profile
        id = request.user.id
        if id != id:
            return Response({'message': 'You are not authorized to view this profile'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = AccountSerializer(request.user)
        response_data = {
            "data": serializer.data,
            "message": f"User profile of {request.user.id} fetched successfully"
        }
        return Response(response_data, status=status.HTTP_200_OK)
    
    def patch(self, request, id=None):
        # Ensure the user can only update their own profile
        id = request.user.id
        if id != id:
            return Response({'message': 'You are not authorized to update this profile'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = AccountSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            response_data = {
                "data": serializer.data,
                "message": f"User profile of {request.user.id} updated successfully"
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, id=None):
        # Ensure the user can only delete their own profile
        id = request.user.id
        if id != id:
            return Response({'message': 'You are not authorized to delete this profile'}, status=status.HTTP_401_UNAUTHORIZED)
        request.user.delete()
        return Response({'message': f'User id deleted successfully'}, status=status.HTTP_204_NO_CONTENT)