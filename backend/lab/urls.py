from django.urls import path
from . import views

urlpatterns = [
    # Yangi thesis endpointlari
    path('windows/',         views.log_windows),       # LogWindow ro'yxati
    path('windows/export/',  views.export_csv),        # CSV export
    path('dataset/generate/',views.generate_dataset),  # Synthetic data
    path('simulate/',        views.run_simulation),    # Hujum simulyatsiyasi
    path('train/',           views.train_model),       # Model o'qitish
    path('train/status/',    views.train_status),      # Train holati
    path('predict/',         views.predict),           # Bashorat
    path('metrics/',         views.model_metrics),     # Model metrikalar
    path('collect/',         views.collect_now),       # Bir marta log yig'ish
    path('history/',         views.prediction_history), # Bashorat tarixi
    path('scenario/',        views.run_scenario),       # To'liq demo stsenariy
    path('report/pdf/',      views.export_pdf_report),  # PDF hisobot
    path('history/export/',  views.export_history_csv), # Bashorat tarixi CSV
]
