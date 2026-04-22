from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'threats', views.ThreatLogViewSet)
router.register(r'blocked', views.BlockedIPViewSet)
router.register(r'network/profiles', views.ConnectionProfileViewSet, basename='network-profiles')
router.register(r'network/sessions', views.ScanSessionViewSet, basename='network-sessions')

urlpatterns = [
    path('', include(router.urls)),
    path('dashboard/', views.dashboard_stats),
    path('analyze/', views.analyze_ip),
    path('network/interfaces/', views.network_interfaces),
    path('network/wifi/status/', views.wifi_status),
    path('network/wifi/connect/', views.wifi_connect),
    path('network/scan/', views.scan_local_network),
    path('reputation/<str:ip>/', views.ip_reputation),
    path('logs/live/', views.live_logs),
]
