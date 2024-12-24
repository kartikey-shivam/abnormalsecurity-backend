from django.contrib import admin
from .models import EncryptedFile, FileShare

@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ('original_filename', 'uploaded_by', 'uploaded_at')
    list_filter = ('uploaded_at',)
    search_fields = ('original_filename', 'uploaded_by__username')
    readonly_fields = ('uploaded_at',)

@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    list_display = ('file', 'shared_by', 'shared_with', 'permission', 'expires_at')
    list_filter = ('permission', 'expires_at')
    search_fields = ('file__original_filename', 'shared_by__username', 'shared_with__username')
    readonly_fields = ('created_at',) 