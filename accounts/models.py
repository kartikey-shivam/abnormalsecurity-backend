from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('regular', 'Regular User'),
        ('guest', 'Guest'),
    ]
    
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    is_mfa_enabled = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='regular')
    
    def __str__(self):
        return self.email
    
    @property
    def is_admin_role(self):
        return self.role == 'admin' or self.is_superuser
    
    @property
    def is_regular_role(self):
        return self.role == 'regular'
    
    @property
    def is_guest_role(self):
        return self.role == 'guest'