from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from .serializers import UserSerializer, RegisterSerializer, MFATokenSerializer
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
from .permissions import IsAdminRole

User = get_user_model()

class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.AllowAny]
    
    @action(detail=False, methods=['post'])
    def register(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            # Default role is 'guest' unless specified and user is admin
            role = request.data.get('role', 'guest')
            if role != 'guest' and not (request.user and request.user.is_admin_role):
                role = 'guest'
                
            user = serializer.save(role=role)
            return Response({
                'message': 'User registered successfully',
                'user': UserSerializer(user).data
            })
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def login(self, request):
        user = User.objects.filter(username=request.data.get('username')).first()
        if user and user.check_password(request.data.get('password')):
            if user.is_mfa_enabled:
                # Return temporary token for MFA
                token = RefreshToken.for_user(user)
                token['mfa_required'] = True
                return Response({
                    'token': str(token.access_token),
                    'mfa_required': True
                })
            # Return full access token
            token = RefreshToken.for_user(user)
            return Response({
                'refresh': str(token),
                'access': str(token.access_token)
            })
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    @action(detail=False, methods=['post'])
    def verify_mfa(self, request):
        token = request.data.get('token')
        mfa_code = request.data.get('mfa_code')
        
        # Verify MFA code
        user = request.user
        device = TOTPDevice.objects.filter(user=user).first()
        if device and device.verify_token(mfa_code):
            # Return full access token
            token = RefreshToken.for_user(user)
            return Response({
                'refresh': str(token),
                'access': str(token.access_token)
            })
        return Response({'error': 'Invalid MFA code'}, status=status.HTTP_401_UNAUTHORIZED) 

    @action(detail=False, methods=['post'], permission_classes=[IsAdminRole])
    def change_role(self, request):
        user_id = request.data.get('user_id')
        new_role = request.data.get('role')
        
        if not user_id or not new_role:
            return Response({
                'error': 'Both user_id and role are required'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = User.objects.get(id=user_id)
            user.role = new_role
            user.save()
            return Response({
                'message': 'Role updated successfully',
                'user': UserSerializer(user).data
            })
        except User.DoesNotExist:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND) 