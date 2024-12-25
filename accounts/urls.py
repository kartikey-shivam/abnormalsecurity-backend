from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('setup-mfa/', views.setup_mfa, name='setup_mfa'),
    path('dashboard/', views.dashboard, name='dashboard'),
] 