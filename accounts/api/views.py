from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.contrib.auth import get_user_model
from .serializers import UserSerializer, UserRegistrationSerializer, MFATokenSerializer
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
from .permissions import IsAdminRole
from ..mfa import MFAHandler
from django.conf import settings

User = get_user_model()

class AuthViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegistrationSerializer
    
    def get_serializer_class(self):
        if self.action == 'register':
            return UserRegistrationSerializer
        elif self.action == 'verify_mfa':
            return MFATokenSerializer
        return UserSerializer
    
    @action(detail=False, methods=['post'])
    def register(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                return Response({
                    'message': 'User registered successfully',
                    'user': UserSerializer(user).data
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({
                    'error': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def set_cookie_response(self, response, access_token, refresh_token):
        response.set_cookie(
            settings.SIMPLE_JWT['AUTH_COOKIE'],
            access_token,
            max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH']
        )
        response.set_cookie(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
            refresh_token,
            max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
            path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH']
        )

    @action(detail=False, methods=['post'])
    def login(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        user = User.objects.filter(username=username).first()
        if user and user.check_password(password):
            if user.is_mfa_enabled:
                # MFA handling
                mfa_handler = MFAHandler()
                token = mfa_handler.generate_email_token()
                mfa_handler.send_email_token(user, token)
                
                # Create temporary token
                refresh = RefreshToken.for_user(user)
                response = Response({
                    'mfa_required': True,
                    'message': 'MFA code sent to your email'
                })
                response.set_cookie(
                    'temp_token',
                    str(refresh.access_token),
                    max_age=300,  # 5 minutes
                    httponly=False,
                    samesite='Lax',
                    secure=False,
                    domain='localhost',
                    path='/'
                )
                return response

            # Regular login without MFA
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            response = Response({'message': 'Login successful'})
            response.set_cookie(
                'access_token',
                access_token,
                max_age=3600,
                httponly=False,
                samesite='Lax',
                secure=False,
                domain='localhost',
                path='/'
            )
            
          
            
            return response

        return Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    @action(detail=False, methods=['post'])
    def logout(self, request):
        response = Response({'message': 'Logout successful'})
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        return response

    @action(detail=False, methods=['post'], url_path='verify-mfa')
    def verify_mfa(self, request):
        temp_token = request.COOKIES.get('temp_token')
        if not temp_token:
            return Response(
                {'error': 'No temporary token found'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        try:
            # Validate temp token and get user
            token = AccessToken(temp_token)
            user = User.objects.get(id=token['user_id'])
            
            mfa_code = request.data.get('mfa_code')
            mfa_handler = MFAHandler()
            
            if mfa_handler.verify_token(user, mfa_code):
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                
                response = Response({
                    'message': 'MFA verification successful'
                })
                
                response.set_cookie(
                    'access_token',
                    access_token,
                    max_age=3600,
                    httponly=False,
                    samesite='Lax',
                    secure=False,
                    domain='localhost',
                    path='/'
                )
                
                response.delete_cookie('temp_token')
                return response

            return Response(
                {'error': 'Invalid MFA code'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_401_UNAUTHORIZED
            )

    @action(detail=False, methods=['post'], permission_classes=[IsAdminRole])
    def change_role(self, request):
        email = request.data.get('email')
        new_role = request.data.get('role')
        
        if not email or not new_role:
            return Response({
                'error': 'Both email and role are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if new_role not in ['admin', 'regular', 'guest']:
            return Response({
                'error': 'Invalid role. Must be one of: admin, regular, guest'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = User.objects.get(email=email)
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

    @action(detail=False, methods=['get'], url_path='user-info/(?P<user_id>[^/.]+)')
    def user_info(self, request, user_id=None):
        try:
            user = User.objects.get(id=user_id)
            return Response({
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'role': user.role,
                'is_mfa_enabled': user.is_mfa_enabled
            })
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'}, 
                status=status.HTTP_404_NOT_FOUND
            ) 

    @action(detail=False, methods=['post'])
    def setup_mfa(self, request):
        """Initial MFA setup with verification"""
        user = request.user
        if user.is_mfa_enabled:
            return Response({
                'error': 'MFA is already set up'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Generate initial setup code
            mfa_handler = MFAHandler()
            setup_token = mfa_handler.generate_setup_token()
            
            # Store setup token temporarily
            user.mfa_setup_token = setup_token
            user.save()
            
            return Response({
                'message': 'MFA setup initiated',
                'setup_token': setup_token,
                'next_step': 'Verify this token using verify-mfa endpoint'
            })
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def enable_mfa(self, request):
        """Toggle MFA state after it's been set up"""
        user = request.user
        enable = request.data.get('enable', True)
        
        if enable and user.is_mfa_enabled:
            return Response({
                'error': 'MFA is already enabled'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not enable and not user.is_mfa_enabled:
            return Response({
                'error': 'MFA is already disabled'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user.is_mfa_enabled = enable
            user.save()
            message = 'MFA enabled successfully' if enable else 'MFA disabled successfully'
            return Response({
                'message': message
            })
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def disable_mfa(self, request):
        user = request.user
        if not user.is_mfa_enabled:
            return Response({
                'error': 'MFA is already disabled'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user.is_mfa_enabled = False
            user.save()
            return Response({
                'message': 'MFA disabled successfully'
            })
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 