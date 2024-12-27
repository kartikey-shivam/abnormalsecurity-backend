from rest_framework import serializers
from django_otp.plugins.otp_totp.models import TOTPDevice

class TOTPSetupSerializer(serializers.Serializer):
    token = serializers.CharField(required=False)

class TOTPVerifySerializer(serializers.Serializer):
    token = serializers.CharField(required=True)

class TOTPDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = TOTPDevice
        fields = ['name', 'confirmed'] 