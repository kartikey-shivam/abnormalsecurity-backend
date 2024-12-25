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
from .permissions import CanUploadFile

User = get_user_model()

class FileViewSet(viewsets.ModelViewSet):
    serializer_class = EncryptedFileSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    queryset = EncryptedFile.objects.all()
    permission_classes = [permissions.IsAuthenticated, CanUploadFile]

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'share', 'destroy']:
            permission_classes = [IsRegularRole]
        elif self.action in ['shared_with_me', 'my_shares']:
            permission_classes = [permissions.IsAuthenticated]
        else:
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
        """
        Share a file either publicly or with specific users
        share_type: 'public' or 'private'
        permission: 'view' or 'download'
        expires_in_days: number of days until share expires
        users: list of user emails (required for private sharing)
        """
        if not request.user.is_regular_role and not request.user.is_admin_role:
            raise PermissionDenied("Only regular users and admins can share files")
        
        file_obj = self.get_object()
        share_type = request.data.get('share_type')
        permission = request.data.get('permission', 'view')
        expires_in_days = request.data.get('expires_in_days', 7)  # Default 7 days
        
        if permission not in ['view', 'download']:
            return Response({
                'error': 'Permission must be either "view" or "download"'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Calculate expiration date
            expires_at = timezone.now() + timezone.timedelta(days=expires_in_days)
            
            if share_type == 'public':
                # Create or update public share
                public_share, created = FileShare.objects.update_or_create(
                    file=file_obj,
                    is_public=True,
                    defaults={
                        'shared_by': request.user,
                        'permission': permission,
                        'expires_at': expires_at
                    }
                )
                return Response({
                    'message': 'File shared publicly',
                    'share_id': public_share.id,
                    'expires_at': expires_at
                })
                
            elif share_type == 'private':
                # Get list of user emails to share with
                user_emails = request.data.get('users', [])
                if not user_emails:
                    return Response({
                        'error': 'Must provide list of user emails for private sharing'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Find users and create shares
                shared_with = []
                not_found = []
                for email in user_emails:
                    try:
                        user = User.objects.get(email=email)
                        share = FileShare.objects.create(
                            file=file_obj,
                            shared_by=request.user,
                            shared_with=user,
                            permission=permission,
                            expires_at=expires_at,
                            is_public=False
                        )
                        shared_with.append(email)
                    except User.DoesNotExist:
                        not_found.append(email)
                
                return Response({
                    'message': 'File shared with users',
                    'shared_with': shared_with,
                    'not_found': not_found,
                    'expires_at': expires_at
                })
                
            else:
                return Response({
                    'error': 'share_type must be either "public" or "private"'
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

    @action(detail=False, methods=['get'], url_path='my-files')
    def get_user_files(self, request):
        """Get all files uploaded by the current user"""
        try:
            files = EncryptedFile.objects.filter(uploaded_by=request.user)
            serializer = EncryptedFileSerializer(files, many=True)
            return Response({
                'files': serializer.data
            })
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 

    def destroy(self, request, *args, **kwargs):
        """Delete a file"""
        file_obj = self.get_object()
        # Check if user is the owner of the file
        if file_obj.uploaded_by != request.user and not request.user.is_admin_role:
            return Response({
                'error': 'You can only delete your own files'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Delete the file
            file_obj.delete()
            return Response({
                'message': 'File deleted successfully'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 

    @action(detail=False, methods=['get'], url_path='shared-with-me')
    def shared_with_me(self, request):
        """List files shared with me (both public and private shares)"""
        try:
            # Get private shares for the user that haven't expired
            private_shares = FileShare.objects.select_related('file', 'shared_by').filter(
                shared_with=request.user,
                is_public=False,
                expires_at__gt=timezone.now()
            )

            # Get public shares that haven't expired
            public_shares = FileShare.objects.select_related('file', 'shared_by').filter(
                is_public=True,
                expires_at__gt=timezone.now()
            ).exclude(shared_by=request.user)  # Exclude self-shared files

            # Combine and serialize the data
            all_shares = private_shares.union(public_shares)
            
            data = []
            for share in all_shares:
                try:
                    data.append({
                        'file_id': share.file.id,
                        'filename': share.file.original_filename,
                        'shared_by': share.shared_by.email,
                        'shared_at': share.created_at.isoformat(),
                        'expires_at': share.expires_at.isoformat(),
                        'permission': share.permission,
                        'is_public': share.is_public,
                        'share_id': share.id
                    })
                except Exception as e:
                    print("Error processing share {}: {}".format(share.id, str(e)))
                    continue

            return Response({
                'shared_files': data
            })
        except Exception as e:
            print("Error in shared_with_me: {}".format(str(e)))
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='my-shares')
    def my_shares(self, request):
        """List files I have shared with others"""
        try:
            # Get all shares created by the user
            shares = FileShare.objects.select_related('file', 'shared_with').filter(
                shared_by=request.user
            )

            data = []
            for share in shares:
                try:
                    share_data = {
                        'file_id': share.file.id,
                        'filename': share.file.original_filename,
                        'created_at': share.created_at.isoformat(),
                        'expires_at': share.expires_at.isoformat(),
                        'permission': share.permission,
                        'is_public': share.is_public,
                        'is_expired': share.is_expired,
                        'share_id': share.id
                    }

                    if not share.is_public and share.shared_with:
                        share_data['shared_with'] = share.shared_with.email

                    data.append(share_data)
                except Exception as e:
                    print("Error processing share {}: {}".format(share.id, str(e)))
                    continue

            return Response({
                'my_shares': data
            })
        except Exception as e:
            print("Error in my_shares: {}".format(str(e)))
            return Response({
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR) 