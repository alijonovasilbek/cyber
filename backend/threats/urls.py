from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'threats', views.ThreatLogViewSet)
router.register(r'logs', views.TrafficEventLogViewSet, basename='logs')
router.register(r'blocked', views.BlockedIPViewSet)
router.register(r'ip-analysis', views.IPAnalysisRecordViewSet, basename='ip-analysis')
router.register(r'network/profiles', views.ConnectionProfileViewSet, basename='network-profiles')
router.register(r'network/sessions', views.ScanSessionViewSet, basename='network-sessions')

urlpatterns = [
    path('logs/live/', views.live_logs),
    path('dashboard/', views.dashboard_stats),
    path('analyze/', views.analyze_ip),
    path('scan-ip/', views.safe_scan_ip),
    path('simulate-traffic/', views.simulate_traffic_view),
    path('predict/', views.predict_threat),
    path('intel/', views.target_intel),
    path('network/interfaces/', views.network_interfaces),
    path('network/wifi/status/', views.wifi_status),
    path('network/wifi/connect/', views.wifi_connect),
    path('network/scan/', views.scan_local_network),
    path('local-agent/download/<str:script_name>/', views.download_local_agent_script),
    path('reputation/<str:ip>/', views.ip_reputation),
    path('', include(router.urls)),
]
