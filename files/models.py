from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid
from cryptography.fernet import Fernet
from datetime import timedelta

def generate_encrypted_filename(instance, filename):
    """Generate a unique filename for encrypted files"""
    return 'enc/{}.bin'.format(uuid.uuid4().hex[:8])

class EncryptedFile(models.Model):
    file = models.FileField(upload_to=generate_encrypted_filename)
    original_filename = models.CharField(max_length=255)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    encryption_key = models.BinaryField()
    
    def __str__(self):
        return self.original_filename

class FileShare(models.Model):
    PERMISSION_CHOICES = [
        ('view', 'View Only'),
        ('download', 'Download Allowed')
    ]
    
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE)
    shared_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shares_created')
    shared_with = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shares_received', null=True, blank=True)
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='view')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_public = models.BooleanField(default=False)
    share_link = models.UUIDField(default=uuid.uuid4, editable=False)

    class Meta:
        unique_together = ['file', 'shared_with']

    def __str__(self):
        if self.is_public:
            return "Public share of {}".format(self.file.original_filename)
        return "Share of {} with {}".format(self.file.original_filename, self.shared_with)

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at 

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(days=self.expire_days)
        super().save(*args, **kwargs) 