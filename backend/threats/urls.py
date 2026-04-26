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
    path('predict/', views.predict_threat),
    path('intel/', views.target_intel),
    path('network/interfaces/', views.network_interfaces),
    path('network/wifi/status/', views.wifi_status),
    path('network/wifi/connect/', views.wifi_connect),
    path('network/scan/', views.scan_local_network),
    path('local-agent/download/<str:script_name>/', views.download_local_agent_script),
    path('reputation/<str:ip>/', views.ip_reputation),
    # ── Yangi endpointlar ───────────────────────────────────────────────────
    path('model/performance/', views.model_performance),
    path('model/attribution/', views.feature_attribution),
    path('model/autoencoder/', views.autoencoder_analysis),
    path('dataset/upload/', views.dataset_upload),
    path('dataset/list/', views.dataset_list),
    path('dataset/samples/', views.sample_datasets_list),
    path('dataset/sample/<str:dataset_id>/', views.sample_dataset_download),
    path('dashboard/timeline/', views.threat_timeline),
    path('heatmap/', views.heatmap_data),
    path('mitre/', views.mitre_list),
    path('incidents/', views.incidents),
    path('cluster/', views.cluster_view),
    path('export/csv/', views.export_csv),
    path('export/json/', views.export_json_data),
    path('export/pdf/', views.export_pdf),
    # ── Yangi xususiyatlar ───────────────────────────────────────────────────
    path('xai/', views.xai_explanation),
    path('lstm/', views.lstm_predict),
    path('geoip/', views.geoip_lookup),
    path('auto-block/', views.auto_block_view),
    path('auto-unblock/', views.auto_unblock_view),
    path('telegram/test/', views.telegram_test_view),
    path('behavior/', views.user_behavior_view),
    path('run-migration/', views.run_pending_migrations),
    path('', include(router.urls)),
]
