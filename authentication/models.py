from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    phone_number = models.CharField(max_length=15)
    role = models.CharField(max_length=10, choices=[
        ('admin', 'Admin'),
        ('user', 'User'),
        ('guest', 'Guest')
    ], default='user')
    mfa_secret = models.CharField(max_length=32, null=True, blank=True)
    mfa_enabled = models.BooleanField(default=False) 