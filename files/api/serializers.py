from rest_framework import serializers
from ..models import EncryptedFile, FileShare

class EncryptedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncryptedFile
        fields = ('id', 'original_filename', 'uploaded_at')
        read_only_fields = ('id', 'uploaded_at')

class FileShareSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileShare
        fields = ('id', 'file', 'shared_with', 'permission', 'expires_at') 