from rest_framework import serializers
from django.contrib.auth import get_user_model
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'phone_number')
        read_only_fields = ('id',)

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, default='guest')
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'phone_number', 'role')

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class MFATokenSerializer(serializers.Serializer):
    token = serializers.CharField() 