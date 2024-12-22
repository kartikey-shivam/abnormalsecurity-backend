from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid
from cryptography.fernet import Fernet

class EncryptedFile(models.Model):
    file = models.FileField(upload_to='encrypted_files/')
    original_filename = models.CharField(max_length=255)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    encryption_key = models.BinaryField()
    
    def __str__(self):
        return self.original_filename

class FileShare(models.Model):
    PERMISSION_CHOICES = [
        ('view', 'View Only'),
        ('download', 'Download'),
    ]
    
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE)
    shared_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_by')
    shared_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_with', null=True, blank=True)
    share_link = models.UUIDField(default=uuid.uuid4, unique=True)
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='view')
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    @property
    def is_expired(self):
        return timezone.now() > self.expires_at 