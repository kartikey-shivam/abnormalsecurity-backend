from django.core.exceptions import ValidationError, PermissionDenied
from django.db import models
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.http import FileResponse, HttpResponse
from django.core.files.base import ContentFile
import os
from django.core.files.storage import default_storage
from django.contrib.auth import get_user_model
from accounts.api.serializers import UserSerializer

from ..models import EncryptedFile, FileShare
from ..permissions import IsAdminRole, IsRegularRole, IsGuestRole
from ..validators import validate_file_type
from ..encryption import AESCipher
from .serializers import EncryptedFileSerializer, FileShareSerializer

User = get_user_model()

class FileViewSet(viewsets.ModelViewSet):
    serializer_class = EncryptedFileSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

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
        file_obj = self.request.FILES.get('file')
        if not file_obj:
            raise ValidationError({'file': 'No file was submitted'})
            
        if file_obj:
            # Validate file type
            try:
                validate_file_type(file_obj)
            except ValidationError as e:
                raise ValidationError({'file': str(e)})

            cipher = AESCipher()
            encrypted_data = cipher.encrypt(file_obj.read())
            serializer.save(
                uploaded_by=self.request.user,
                file=encrypted_data,
                original_filename=file_obj.name,
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
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        file_obj = self.get_object()
        
        # Check if user has permission to download
        if request.user == file_obj.uploaded_by:
            can_download = True
        else:
            share = FileShare.objects.filter(
                file=file_obj,
                shared_with=request.user,
                permission='download',
                expires_at__gt=timezone.now()
            ).first()
            can_download = bool(share)

        if not can_download:
            return Response(
                {'error': 'You do not have permission to download this file'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            cipher = AESCipher()
            cipher.key = file_obj.encryption_key
            
            # Get the file content directly from the FileField
            file_content = file_obj.file.read()
            decrypted_data = cipher.decrypt(file_content)
            
            # Create a temporary file-like object
            temp_file = ContentFile(decrypted_data)
            
            # Use FileResponse for better streaming
            response = FileResponse(
                temp_file,
                as_attachment=True,
                filename=file_obj.original_filename
            )
            return response

        except Exception as e:
            return Response(
                {'error': 'Error downloading file: {}'.format(str(e))},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 

    @action(detail=False, methods=['post'], permission_classes=[IsAdminRole])
    def change_role(self, request):
        email = request.data.get('email')
        new_role = request.data.get('role')
        
        if not email or not new_role:
            return Response({
                'error': 'Both email and role are required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if new_role not in ['admin', 'regular', 'guest']:
            return Response({
                'error': 'Invalid role. Must be one of: admin, regular, guest'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = User.objects.get(email=email)
            user.role = new_role
            user.save()
            return Response({
                'message': 'Role updated successfully',
                'user': UserSerializer(user).data
            })
        except User.DoesNotExist:
            return Response({
                'error': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND) 