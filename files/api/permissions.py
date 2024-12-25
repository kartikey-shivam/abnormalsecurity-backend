from rest_framework import permissions

class CanUploadFile(permissions.BasePermission):
    """
    Custom permission to only allow admin and regular users to upload files.
    """
    def has_permission(self, request, view):
        # Allow read operations for all authenticated users
        if request.method in permissions.SAFE_METHODS:
            return True
            
        # Check if user has permission to upload
        return request.user.is_authenticated and request.user.role in ['admin', 'regular'] 