from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.core.mail import send_mail
from django.conf import settings
import random
import logging
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.shortcuts import render

logger = logging.getLogger(__name__)

class MFAViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def generate_verification_code(self):
        """Generate a 6-digit verification code"""
        code = str(random.randint(100000, 999999))
        print("Generated verification code: {}".format(code))
        return code

    def send_verification_email(self, user, code):
        """Send verification code via email"""
        try:
            print("\n=== Starting Email Send Process ===")
            print("Sending to user: {}".format(user.email))
            print("Verification code: {}".format(code))

            subject = 'Your Security Verification Code'
            message = (
                "Hello,\n\n"
                "Your verification code is: {}\n\n"
                "This code will expire in 10 minutes.\n\n"
                "If you didn't request this code, please ignore this email.\n\n"
                "Best regards,\nSecure File Share Team"
            ).format(code)
            
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [user.email]

            # Send email
            result = send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                fail_silently=False
            )
            
            print("Email sent successfully")
            return True

        except Exception as e:
            print("Failed to send email: {}".format(str(e)))
            return False

    @action(detail=False, methods=['post'])
    def setup_mfa(self, request):
        """
        Setup MFA for a user by sending verification code via email
        """
        try:
            user = request.user
            print("\n=== Starting MFA Setup ===")
            print("User: {}".format(user.email))
            
            # Delete any existing TOTP devices and reset MFA status
            TOTPDevice.objects.filter(user=user).delete()
            user.is_mfa_enabled = False
            user.save(update_fields=['is_mfa_enabled'])
            
            print("Deleted existing TOTP devices")
            
            # Generate verification code
            verification_code = self.generate_verification_code()
            print("Generated verification code: {}".format(verification_code))
            
            # Create new TOTP device
            device = TOTPDevice.objects.create(
                user=user,
                name='Email-based MFA',
                confirmed=False,
                key=verification_code
            )
            print("Created TOTP device")

            # Send verification code via email
            print("Attempting to send verification email...")
            email_sent = self.send_verification_email(user, verification_code)
            
            if email_sent:
                print("=== MFA Setup Successful ===\n")
                return Response({
                    'message': 'Verification code sent to your email',
                    'email': user.email,
                    'status': 'success'
                })
            else:
                print("=== MFA Setup Failed - Email Not Sent ===\n")
                device.delete()
                return Response({
                    'error': 'Failed to send verification code. Please try again.',
                    'status': 'error'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            print("\n=== MFA Setup Failed - Exception ===")
            print("Error: {}".format(str(e)))
            return Response({
                'error': 'Setup failed: {}'.format(str(e)),
                'status': 'error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def verify_mfa(self, request):
        """
        Verify the email-based MFA code
        """
        try:
            code = request.data.get('code')
            print("\n=== Starting MFA Verification ===")
            print("Received code: {}".format(code))
            
            if not code:
                print("No code provided")
                return Response({
                    'error': 'Verification code is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            device = TOTPDevice.objects.filter(user=request.user, confirmed=False).first()
            if not device:
                print("No unconfirmed device found for user: {}".format(request.user.email))
                return Response({
                    'error': 'MFA setup not initiated'
                }, status=status.HTTP_400_BAD_REQUEST)

            print("Stored code: {}".format(device.key))
            print("Comparing received code '{}' with stored code '{}'".format(code, device.key))

            # Verify the code
            stored_code = str(device.key).strip()
            received_code = str(code).strip()
            
            if received_code == stored_code:
                print("Code verified successfully")
                device.confirmed = True
                device.save()
                
                # Update user's MFA status
                user = request.user
                user.is_mfa_enabled = True
                user.save(update_fields=['is_mfa_enabled'])
                print("Updated user's MFA status to enabled")

                print("=== MFA Verification Successful ===\n")
                return Response({
                    'message': 'MFA activated successfully',
                    'status': 'success'
                })
            
            print("Code verification failed")
            print("=== MFA Verification Failed ===\n")
            return Response({
                'error': 'Invalid verification code'
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            print("\n=== MFA Verification Failed - Exception ===")
            print("Error: {}".format(str(e)))
            return Response({
                'error': 'Verification failed: {}'.format(str(e)),
                'status': 'error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def disable_mfa(self, request):
        """
        Disable MFA for the user
        """
        try:
            # Get the user's MFA devices
            devices = TOTPDevice.objects.filter(user=request.user)
            
            if not devices.exists():
                return Response({
                    'message': 'MFA is not enabled for this user'
                })

            # Delete all MFA devices for the user
            devices_count = devices.count()
            devices.delete()

            # Update user's MFA status
            user = request.user
            user.is_mfa_enabled = False
            user.save(update_fields=['is_mfa_enabled'])
            print("Updated user's MFA status to disabled")

            return Response({
                'message': "MFA disabled successfully. Removed {} device(s)".format(devices_count),
                'status': 'success'
            })
            
        except Exception as e:
            return Response({
                'error': "Failed to disable MFA: {}".format(str(e))
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'])
    def mfa_status(self, request):
        """
        Get MFA status for the user
        """
        user = request.user
        device = TOTPDevice.objects.filter(user=user, confirmed=True).first()
        is_mfa_enabled = bool(device)
        
        # Sync MFA status if it's out of sync
        if user.is_mfa_enabled != is_mfa_enabled:
            user.is_mfa_enabled = is_mfa_enabled
            user.save(update_fields=['is_mfa_enabled'])
        
        return Response({
            'mfa_enabled': is_mfa_enabled
        })

@api_view(['GET'])
def test_template(request):
    """Test template rendering"""
    try:
        html = render_to_string(
            'authentication/email/mfa_verification.html',
            {
                'user': request.user,
                'code': '123456',
                'company_name': 'Secure File Share',
                'support_email': 'katikey.saraswat301@gmail.com'
            }
        )
        return Response({
            'html': html,
            'status': 'success'
        })
    except Exception as e:
        return Response({
            'error': str(e),
            'status': 'error'
        }, status=500) 

@api_view(['GET'])
def debug_template_paths(request):
    """Debug view to check template configuration"""
    from django.template.loader import get_template
    from django.conf import settings
    
    template_name = 'authentication/email/mfa_verification.html'
    
    debug_info = {
        'template_dirs': settings.TEMPLATES[0]['DIRS'],
        'app_dirs_enabled': settings.TEMPLATES[0]['APP_DIRS'],
        'template_name': template_name,
        'base_dir': str(settings.BASE_DIR),
    }
    
    try:
        template = get_template(template_name)
        debug_info['template_found'] = True
        debug_info['template_path'] = template.origin.name
    except Exception as e:
        debug_info['template_found'] = False
        debug_info['error'] = str(e)
    
    return Response(debug_info) 