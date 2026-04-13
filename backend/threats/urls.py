from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'threats', views.ThreatLogViewSet)
router.register(r'blocked', views.BlockedIPViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('dashboard/', views.dashboard_stats),
    path('analyze/', views.analyze_ip),
    path('network/scan/', views.scan_local_network),
    path('reputation/<str:ip>/', views.ip_reputation),
    path('logs/live/', views.live_logs),
]
