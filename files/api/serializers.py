from rest_framework import serializers
from django.contrib.auth import get_user_model
from ..models import EncryptedFile, FileShare

User = get_user_model()

class EncryptedFileSerializer(serializers.ModelSerializer):
    file = serializers.FileField(required=True)
    
    class Meta:
        model = EncryptedFile
        fields = ('id', 'file', 'original_filename', 'uploaded_at')
        read_only_fields = ('id', 'uploaded_at', 'original_filename')

class FileShareSerializer(serializers.ModelSerializer):
    shared_with = serializers.CharField(write_only=True)  # Accept username/email as string

    class Meta:
        model = FileShare
        fields = ['shared_with', 'permission', 'expire_days']
        extra_kwargs = {
            'shared_with': {'required': True},
            'permission': {'required': True},
            'expire_days': {'required': False, 'default': 7}
        }

    def validate_shared_with(self, value):
        try:
            # Try to find user by username or email
            user = User.objects.get(email=value)
            return user
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

    def create(self, validated_data):
        # validated_data['shared_with'] is now a User instance
        return super().create(validated_data) 