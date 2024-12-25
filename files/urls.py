from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.upload_file, name='upload_file'),
    path('files/', views.file_list, name='file_list'),
    path('files/<int:pk>/', views.file_detail, name='file_detail'),
    path('files/<int:pk>/download/', views.download_file, name='download_file'),
    path('share/<uuid:uuid>/', views.shared_file_access, name='shared_file_access'),
] 