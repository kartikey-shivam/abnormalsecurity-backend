from django.core.mail import send_mail
import random
from django.core.cache import cache

class MFAHandler:
    @staticmethod
    def generate_email_token():
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def send_email_token(user, token):
        # Store token in cache for 10 minutes
        cache_key = 'mfa_token_{}'.format(user.id)
        cache.set(cache_key, token, timeout=600)  # 600 seconds = 10 minutes
        
        send_mail(
            'Your MFA Code',
            'Your verification code is: {}'.format(token),
            'noreply@yourapp.com',
            [user.email],
            fail_silently=False,
        )
    
    @staticmethod
    def verify_token(user, token):
        cache_key = 'mfa_token_{}'.format(user.id)
        stored_token = cache.get(cache_key)
        if stored_token and stored_token == token:
            cache.delete(cache_key)  # Clear the token after successful verification
            return True
        return False 