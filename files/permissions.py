from rest_framework import permissions

class IsAdminRole(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_admin_role

class IsRegularRole(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and (
            request.user.is_regular_role or request.user.is_admin_role
        )

class IsGuestRole(permissions.BasePermission):
    def has_permission(self, request, view):
        # Guests can only view shared files
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        return False 