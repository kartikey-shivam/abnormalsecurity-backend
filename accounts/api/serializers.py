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

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('email', 'username', 'password')
        extra_kwargs = {
            'email': {
                'required': True,
                'error_messages': {
                    'unique': "A user with that email already exists."
                }
            }
        }

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user

class MFATokenSerializer(serializers.Serializer):
    token = serializers.CharField() 