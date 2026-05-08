import csv
import io
import threading
import logging
from datetime import datetime

from django.http import HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import LogWindow, TrainSession, PredictionLog

logger = logging.getLogger(__name__)


# ── LogWindow ro'yxati ────────────────────────────────────────────────────

@api_view(['GET'])
def log_windows(request):
    limit  = min(int(request.GET.get('limit', 100)), 1000)
    label  = request.GET.get('label')
    source = request.GET.get('source')

    qs = LogWindow.objects.order_by('-timestamp')
    if label:
        qs = qs.filter(label=label)
    if source:
        qs = qs.filter(source=source)

    rows = list(qs[:limit].values(
        'id', 'timestamp', 'failed_logins', 'success_logins',
        'new_processes', 'policy_changes', 'service_events',
        'tcp_connections', 'running_processes', 'label', 'source',
    ))
    return Response({'count': len(rows), 'results': rows})


# ── CSV export ────────────────────────────────────────────────────────────

@api_view(['GET'])
def export_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="log_windows.csv"'

    fields = [
        'timestamp', 'failed_logins', 'success_logins', 'new_processes',
        'policy_changes', 'service_events', 'tcp_connections',
        'running_processes', 'label', 'source',
    ]
    writer = csv.DictWriter(response, fieldnames=fields)
    writer.writeheader()
    for row in LogWindow.objects.order_by('timestamp').values(*fields):
        writer.writerow(row)

    return response


# ── Synthetic dataset ─────────────────────────────────────────────────────

@api_view(['POST'])
def generate_dataset(request):
    n_normal      = int(request.data.get('n_normal',      300))
    n_brute_force = int(request.data.get('n_brute_force', 150))
    n_port_scan   = int(request.data.get('n_port_scan',   150))
    n_anomaly     = int(request.data.get('n_anomaly',     150))

    from .dataset_generator import generate_dataset as _gen
    rows = _gen(
        n_normal=n_normal,
        n_brute_force=n_brute_force,
        n_port_scan=n_port_scan,
        n_anomaly=n_anomaly,
    )
    total = LogWindow.objects.count()
    return Response({
        'generated': len(rows),
        'total_in_db': total,
        'breakdown': {
            'normal': n_normal,
            'brute_force': n_brute_force,
            'port_scan': n_port_scan,
            'anomaly': n_anomaly,
        },
    })


# ── Simulyatsiya ──────────────────────────────────────────────────────────

@api_view(['POST'])
def run_simulation(request):
    sim_type = request.data.get('type', 'port_scan')
    if sim_type not in ('brute_force', 'port_scan', 'anomaly'):
        return Response({'error': "type: 'brute_force' | 'port_scan' | 'anomaly'"}, status=400)

    from .simulator import run_simulation as _sim
    from .collector import collect_and_save

    result = _sim(sim_type)
    window, counts = collect_and_save(label=sim_type)

    return Response({
        'simulation': result,
        'log_window': {
            'id':                window.pk,
            'timestamp':         window.timestamp,
            'label':             window.label,
            'failed_logins':     window.failed_logins,
            'success_logins':    window.success_logins,
            'new_processes':     window.new_processes,
            'tcp_connections':   window.tcp_connections,
            'running_processes': window.running_processes,
        },
    })


# ── Train ─────────────────────────────────────────────────────────────────

@api_view(['POST'])
def train_model(request):
    session = TrainSession.objects.create(status='pending')

    def _run():
        from .trainer import train
        try:
            train(session_id=session.pk)
        except Exception as e:
            logger.error("Train thread xatosi: %s", e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return Response({
        'session_id': session.pk,
        'status':     'started',
        'message':    "Model o'qitilmoqda. /api/lab/train/status/ dan kuzating.",
    })


@api_view(['GET'])
def train_status(request):
    session = TrainSession.objects.first()
    if not session:
        return Response({'status': 'no_session'})

    return Response({
        'session_id': session.pk,
        'status':     session.status,
        'accuracy':   session.accuracy,
        'f1':         session.f1,
        'precision':  session.precision,
        'recall':     session.recall,
        'roc_auc':    session.roc_auc,
        'train_rows': session.train_rows,
        'error':      session.error_msg or None,
        'created_at': session.created_at,
    })


# ── Predict ───────────────────────────────────────────────────────────────

@api_view(['GET'])
def predict(request):
    from .trainer import predict_next, WINDOW_SIZE

    windows = list(
        LogWindow.objects.order_by('-timestamp')[:WINDOW_SIZE].values(
            'failed_logins', 'success_logins', 'new_processes',
            'policy_changes', 'service_events',
            'tcp_connections', 'running_processes', 'label',
        )
    )
    windows.reverse()

    if len(windows) < WINDOW_SIZE:
        return Response({
            'error': f"Yetarli ma'lumot yo'q. {len(windows)}/{WINDOW_SIZE} ta oyna mavjud."
        }, status=400)

    try:
        result = predict_next(windows)
    except FileNotFoundError:
        return Response({'error': "Model topilmadi. Avval /api/lab/train/ ga POST qiling."}, status=400)

    probs = result['probabilities']
    triggered_by = request.GET.get('triggered_by', 'auto')

    from django.utils import timezone as dj_tz
    PredictionLog.objects.create(
        timestamp        = dj_tz.now(),
        prediction       = result['label'],
        confidence       = result['confidence'],
        prob_normal      = probs.get('normal', 0),
        prob_brute_force = probs.get('brute_force', 0),
        prob_port_scan   = probs.get('port_scan', 0),
        prob_anomaly     = probs.get('anomaly', 0),
        triggered_by     = triggered_by,
    )

    return Response({
        'prediction':        result['label'],
        'confidence':        result['confidence'],
        'probabilities':     probs,
        'based_on_windows':  WINDOW_SIZE,
        'last_real_label':   windows[-1]['label'],
    })


# ── Model metrikalar ──────────────────────────────────────────────────────

@api_view(['POST'])
def collect_now(request):
    """Hozirgi Windows loglarini bir marta o'qib saqlaydi."""
    from .collector import collect_and_save
    label = request.data.get('label', 'normal')
    if label not in ('normal', 'brute_force', 'port_scan', 'anomaly'):
        label = 'normal'
    window, counts = collect_and_save(label=label)
    return Response({
        'id':                window.pk,
        'timestamp':         window.timestamp,
        'label':             window.label,
        'failed_logins':     counts['failed_logins'],
        'success_logins':    counts['success_logins'],
        'new_processes':     counts['new_processes'],
        'tcp_connections':   counts['tcp_connections'],
        'running_processes': counts['running_processes'],
    })


@api_view(['GET'])
def prediction_history(request):
    """So'nggi N ta bashorat natijasini qaytaradi."""
    limit = min(int(request.GET.get('limit', 50)), 200)
    rows = list(PredictionLog.objects.order_by('-timestamp')[:limit].values(
        'id', 'timestamp', 'prediction', 'confidence',
        'prob_normal', 'prob_brute_force', 'prob_port_scan', 'prob_anomaly',
        'triggered_by',
    ))
    return Response({'count': len(rows), 'results': rows})


@api_view(['POST'])
def run_scenario(request):
    """
    To'liq demo stsenariy:
    1. Hujum simulyatsiyasi
    2. Log yig'ish
    3. Bashorat
    Qaytaradi: simulyatsiya natijasi + yig'ilgan log + bashorat
    """
    from .simulator import run_simulation as _sim
    from .collector import collect_and_save
    from .trainer import predict_next, WINDOW_SIZE
    from django.utils import timezone as dj_tz

    sim_type = request.data.get('type', 'port_scan')
    if sim_type not in ('brute_force', 'port_scan', 'anomaly', 'normal'):
        return Response({'error': "type: 'brute_force' | 'port_scan' | 'anomaly' | 'normal'"}, status=400)

    # 1. Simulyatsiya
    sim_result = {}
    if sim_type != 'normal':
        sim_result = _sim(sim_type)

    # 2. Log yig'ish
    window, counts = collect_and_save(label=sim_type)

    # 3. Bashorat
    prediction_result = None
    try:
        recent = list(
            LogWindow.objects.order_by('-timestamp')[:WINDOW_SIZE].values(
                'failed_logins', 'success_logins', 'new_processes',
                'policy_changes', 'service_events',
                'tcp_connections', 'running_processes', 'label',
            )
        )
        recent.reverse()
        if len(recent) >= WINDOW_SIZE:
            prediction_result = predict_next(recent)
            probs = prediction_result['probabilities']
            PredictionLog.objects.create(
                timestamp        = dj_tz.now(),
                prediction       = prediction_result['label'],
                confidence       = prediction_result['confidence'],
                prob_normal      = probs.get('normal', 0),
                prob_brute_force = probs.get('brute_force', 0),
                prob_port_scan   = probs.get('port_scan', 0),
                prob_anomaly     = probs.get('anomaly', 0),
                triggered_by     = 'sim',
            )
    except Exception:
        pass

    return Response({
        'scenario_type': sim_type,
        'simulation':    sim_result,
        'log_window': {
            'id':                window.pk,
            'label':             window.label,
            'tcp_connections':   counts['tcp_connections'],
            'running_processes': counts['running_processes'],
            'failed_logins':     counts['failed_logins'],
        },
        'prediction': prediction_result,
    })


@api_view(['GET'])
def model_metrics(request):
    from .trainer import MODEL_PATH

    session = TrainSession.objects.filter(status='done').first()
    model_exists = MODEL_PATH.exists()

    if not session or not model_exists:
        return Response({'trained': False})

    from collections import Counter
    label_dist = dict(Counter(LogWindow.objects.values_list('label', flat=True)))

    return Response({
        'trained':          True,
        'accuracy':         session.accuracy,
        'f1':               session.f1,
        'precision':        session.precision,
        'recall':           session.recall,
        'roc_auc':          session.roc_auc,
        'train_rows':       session.train_rows,
        'trained_at':       session.created_at,
        'total_windows':    LogWindow.objects.count(),
        'confusion_matrix':   session.confusion_matrix,
        'classes':            session.classes,
        'per_class':          session.per_class,
        'label_distribution': label_dist,
    })


# ── Bashorat tarixi CSV export ─────────────────────────────────────────────

@api_view(['GET'])
def export_history_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="prediction_history.csv"'

    fields = [
        'timestamp', 'prediction', 'confidence',
        'prob_normal', 'prob_brute_force', 'prob_port_scan', 'prob_anomaly',
        'triggered_by',
    ]
    writer = csv.DictWriter(response, fieldnames=fields)
    writer.writeheader()
    for row in PredictionLog.objects.order_by('-timestamp').values(*fields):
        writer.writerow(row)

    return response


# ── PDF hisobot ───────────────────────────────────────────────────────────

@api_view(['GET'])
def export_pdf_report(request):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        return Response({'error': 'reportlab kutubxonasi o\'rnatilmagan.'}, status=500)

    from .trainer import MODEL_PATH
    from collections import Counter

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('title', parent=styles['Heading1'], fontSize=16, spaceAfter=12)
    h2_style    = ParagraphStyle('h2', parent=styles['Heading2'], fontSize=12, spaceAfter=8)
    normal      = styles['Normal']

    story = []
    story.append(Paragraph('CyberGuard — AI Tahdid Bashorat Tizimi', title_style))
    story.append(Paragraph(f"Hisobot sanasi: {datetime.now().strftime('%Y-%m-%d %H:%M')}", normal))
    story.append(Spacer(1, 0.5*cm))

    # Model metrikalar
    session = TrainSession.objects.filter(status='done').first()
    if session and MODEL_PATH.exists():
        story.append(Paragraph('Model Metrikalar', h2_style))
        metrics_data = [
            ['Metrika', 'Qiymat'],
            ['Accuracy',  f"{session.accuracy:.4f}" if session.accuracy else '—'],
            ['F1 Score',  f"{session.f1:.4f}"       if session.f1       else '—'],
            ['Precision', f"{session.precision:.4f}" if session.precision else '—'],
            ['Recall',    f"{session.recall:.4f}"    if session.recall    else '—'],
            ['ROC-AUC',   f"{session.roc_auc:.4f}"  if session.roc_auc  else '—'],
            ['Train rows', str(session.train_rows or '—')],
        ]
        t = Table(metrics_data, colWidths=[8*cm, 8*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
            ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
            ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
            ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN',      (1, 0), (1, -1), 'CENTER'),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.4*cm))

        # Per-class metrikalar
        if session.per_class and session.classes:
            story.append(Paragraph('Har Klass Uchun Metrikalar', h2_style))
            hdr = ['Klass', 'Precision', 'Recall', 'F1']
            rows_pc = [hdr]
            for cls in session.classes:
                m = session.per_class.get(cls, {})
                rows_pc.append([cls,
                                 f"{m.get('precision', 0):.4f}",
                                 f"{m.get('recall',    0):.4f}",
                                 f"{m.get('f1',        0):.4f}"])
            t2 = Table(rows_pc, colWidths=[4*cm, 4*cm, 4*cm, 4*cm])
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
                ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
                ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
                ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN',      (1, 0), (-1, -1), 'CENTER'),
            ]))
            story.append(t2)
            story.append(Spacer(1, 0.4*cm))

        # Confusion matrix
        if session.confusion_matrix and session.classes:
            story.append(Paragraph('Confusion Matrix', h2_style))
            cls_list = session.classes
            cm_hdr = [''] + cls_list
            cm_rows = [cm_hdr]
            for i, row in enumerate(session.confusion_matrix):
                cm_rows.append([cls_list[i]] + [str(v) for v in row])
            col_w = 3.5*cm
            t3 = Table(cm_rows, colWidths=[col_w] * len(cm_hdr))
            t3.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
                ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
                ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#2d6a4f')),
                ('TEXTCOLOR',  (0, 1), (0, -1), colors.white),
                ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
                ('ALIGN',      (1, 1), (-1, -1), 'CENTER'),
            ]))
            story.append(t3)
            story.append(Spacer(1, 0.4*cm))

    # Label taqsimoti
    story.append(Paragraph('Log Window Label Taqsimoti', h2_style))
    label_dist = dict(Counter(LogWindow.objects.values_list('label', flat=True)))
    total_lw = sum(label_dist.values()) or 1
    ld_rows = [['Label', 'Soni', 'Ulushi']]
    for lbl, cnt in sorted(label_dist.items()):
        ld_rows.append([lbl, str(cnt), f"{cnt/total_lw*100:.1f}%"])
    t4 = Table(ld_rows, colWidths=[6*cm, 4*cm, 6*cm])
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
        ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN',      (1, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(t4)
    story.append(Spacer(1, 0.4*cm))

    # So'nggi 20 ta bashorat
    story.append(Paragraph("So'nggi 20 ta Bashorat", h2_style))
    hist_rows = [['Vaqt', 'Bashorat', 'Ishonch', 'Sabab']]
    for p in PredictionLog.objects.order_by('-timestamp')[:20]:
        hist_rows.append([
            p.timestamp.strftime('%Y-%m-%d %H:%M') if p.timestamp else '—',
            p.prediction or '—',
            f"{p.confidence:.2%}" if p.confidence is not None else '—',
            p.triggered_by or '—',
        ])
    t5 = Table(hist_rows, colWidths=[5*cm, 4*cm, 3*cm, 4*cm])
    t5.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a3a5c')),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f0f4f8'), colors.white]),
        ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN',      (2, 1), (2, -1), 'CENTER'),
    ]))
    story.append(t5)

    doc.build(story)
    buf.seek(0)

    response = HttpResponse(buf.read(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="cyberguard_report_{datetime.now().strftime("%Y%m%d_%H%M")}.pdf"'
    return response
