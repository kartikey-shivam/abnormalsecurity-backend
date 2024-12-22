from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from ..models import EncryptedFile, FileShare
from .serializers import EncryptedFileSerializer, FileShareSerializer
from ..encryption import AESCipher
from ..permissions import IsAdminRole, IsRegularRole, IsGuestRole
from django.utils import timezone
from django.core.exceptions import PermissionDenied
from django.db import models

class FileViewSet(viewsets.ModelViewSet):
    serializer_class = EncryptedFileSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'share']:
            # Only admin and regular users can create/update/share files
            permission_classes = [IsRegularRole]
        elif self.action == 'destroy':
            # Only admins can delete files
            permission_classes = [IsAdminRole]
        else:
            # Everyone can view files they have access to
            permission_classes = [IsGuestRole]
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        user = self.request.user
        if user.is_admin_role:
            # Admins can see all files
            return EncryptedFile.objects.all()
        elif user.is_regular_role:
            # Regular users see their files and shared files
            return EncryptedFile.objects.filter(
                models.Q(uploaded_by=user) |
                models.Q(fileshare__shared_with=user)
            ).distinct()
        else:
            # Guests only see files shared with them
            return EncryptedFile.objects.filter(
                fileshare__shared_with=user
            ).distinct()

    def perform_create(self, serializer):
        if not self.request.user.is_regular_role and not self.request.user.is_admin_role:
            raise PermissionDenied("Only regular users and admins can upload files")
            
        file_obj = self.request.FILES.get('file')
        if file_obj:
            cipher = AESCipher()
            encrypted_data = cipher.encrypt(file_obj.read())
            serializer.save(
                uploaded_by=self.request.user,
                file=encrypted_data,
                encryption_key=cipher.key
            )

    @action(detail=True, methods=['post'])
    def share(self, request, pk=None):
        if not request.user.is_regular_role and not request.user.is_admin_role:
            raise PermissionDenied("Only regular users and admins can share files")
            
        file_obj = self.get_object()
        serializer = FileShareSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(
                file=file_obj,
                shared_by=request.user
            )
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 