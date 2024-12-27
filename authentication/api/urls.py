from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import MFAViewSet, test_template, debug_template_paths

router = DefaultRouter()
router.register(r'mfa', MFAViewSet, basename='mfa')

urlpatterns = [
    path('', include(router.urls)),
    path('test-template/', test_template, name='test-template'),
    path('debug-template/', debug_template_paths, name='debug-template'),
] 