"""
Test sample Django views WITHOUT rate limiting for CSEC-26 testing
This file intentionally has authentication views without throttling
"""
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User


# CSEC-26: Login view without throttle_classes - VULNERABLE!
class LoginView(APIView):
    """
    Login endpoint without rate limiting
    SECURITY ISSUE: Vulnerable to brute force attacks
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return Response({
                'message': 'Login successful',
                'user_id': user.id,
                'username': user.username
            })
        else:
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)


# CSEC-26: Signup view without throttle_classes - VULNERABLE!
class SignupView(APIView):
    """
    Signup endpoint without rate limiting
    SECURITY ISSUE: Vulnerable to spam registration
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        if User.objects.filter(username=username).exists():
            return Response({
                'error': 'Username already exists'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )

        return Response({
            'message': 'User created successfully',
            'user_id': user.id
        }, status=status.HTTP_201_CREATED)


# CSEC-26: Password reset view without throttle_classes - VULNERABLE!
class PasswordResetRequestView(APIView):
    """
    Password reset endpoint without rate limiting
    SECURITY ISSUE: Vulnerable to account enumeration
    """
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')

        try:
            user = User.objects.get(email=email)
            # Send password reset email (implementation omitted)
            return Response({
                'message': 'Password reset email sent'
            })
        except User.DoesNotExist:
            # Same response to prevent enumeration
            return Response({
                'message': 'Password reset email sent'
            })


# CSEC-26: MFA verification view without throttle_classes - VULNERABLE!
class MFAVerifyView(APIView):
    """
    MFA verification endpoint without rate limiting
    SECURITY ISSUE: Vulnerable to MFA bypass attempts
    """
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        mfa_code = request.data.get('mfa_code')

        # Verify MFA code (simplified)
        expected_code = self.get_expected_mfa_code(user_id)

        if mfa_code == expected_code:
            return Response({
                'message': 'MFA verification successful',
                'token': 'auth-token-here'
            })
        else:
            return Response({
                'error': 'Invalid MFA code'
            }, status=status.HTTP_401_UNAUTHORIZED)

    def get_expected_mfa_code(self, user_id):
        """Get expected MFA code for user (placeholder)"""
        return '123456'


# CSEC-26: Alternative authentication view formats
class UserAuthLoginView(APIView):
    """Another login view pattern - also missing throttling"""
    permission_classes = [AllowAny]

    def post(self, request):
        # Login logic here
        pass


class RegisterView(APIView):
    """Another signup pattern name - also missing throttling"""
    permission_classes = [AllowAny]

    def post(self, request):
        # Registration logic here
        pass


class TwoFactorVerifyView(APIView):
    """Two-factor auth verification - also missing throttling"""
    permission_classes = [AllowAny]

    def post(self, request):
        # 2FA verification logic here
        pass


# This file should produce 7 findings when scanned with CSEC-26 pattern:
# 1. LoginView
# 2. SignupView
# 3. PasswordResetRequestView
# 4. MFAVerifyView
# 5. UserAuthLoginView
# 6. RegisterView
# 7. TwoFactorVerifyView
