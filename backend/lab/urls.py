from django.urls import path
from . import views

urlpatterns = [
    # ── Mavjud endpointlar ──────────────────────────────────────────────────
    path('windows/',          views.log_windows),
    path('windows/export/',   views.export_csv),
    path('dataset/generate/', views.generate_dataset),
    path('simulate/',         views.run_simulation),
    path('train/',            views.train_model),
    path('train/status/',     views.train_status),
    path('predict/',          views.predict),
    path('metrics/',          views.model_metrics),
    path('collect/',          views.collect_now),
    path('history/',          views.prediction_history),
    path('scenario/',         views.run_scenario),
    path('report/pdf/',       views.export_pdf_report),
    path('history/export/',   views.export_history_csv),

    # ── Victim monitoring ───────────────────────────────────────────────────
    path('victim/status/',    views.victim_status),
    path('victim/logs/',      views.victim_logs),
    path('auto-collect/',     views.auto_collect),

    # ── 3 AI Model ──────────────────────────────────────────────────────────
    path('models/train-all/', views.train_all_models),
    path('models/status/',    views.all_models_status),
    path('models/predict-all/', views.predict_all_models),

    # ── Excel tahlil ────────────────────────────────────────────────────────
    path('upload-excel/',     views.upload_excel),
    path('excel-template/',   views.excel_template),
]
