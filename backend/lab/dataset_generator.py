"""
Realistic labeled dataset yaratadi.

Real loglar yig'ilgunga qadar yoki qo'shimcha trening uchun
ishlatiladi. Har bir label uchun statistik jihatdan to'g'ri
distribusiya qo'llaniladi.

Chiqish: LogWindow yozuvlari (source='synthetic')
"""

import random
import logging
from datetime import timedelta

logger = logging.getLogger(__name__)

# Har bir label uchun feature distribusiyasi: (mean, std, min, max)
DISTRIBUTIONS = {
    'normal': {
        'failed_logins':    (0.2,  0.5,  0, 2),
        'success_logins':   (2.0,  1.5,  0, 8),
        'new_processes':    (3.0,  2.0,  0, 10),
        'policy_changes':   (0.0,  0.1,  0, 1),
        'service_events':   (1.0,  1.0,  0, 5),
        'tcp_connections':  (60.0, 15.0, 10, 100),
        'running_processes':(230.0,20.0, 150, 280),
    },
    'brute_force': {
        'failed_logins':    (45.0, 15.0, 20, 90),
        'success_logins':   (1.0,  1.0,  0, 4),
        'new_processes':    (2.0,  2.0,  0, 8),
        'policy_changes':   (0.1,  0.3,  0, 2),
        'service_events':   (1.0,  1.0,  0, 4),
        'tcp_connections':  (90.0, 20.0, 50, 150),
        'running_processes':(230.0,20.0, 150, 280),
    },
    'port_scan': {
        'failed_logins':    (1.0,  1.5,  0, 5),
        'success_logins':   (1.0,  1.0,  0, 4),
        'new_processes':    (4.0,  2.5,  1, 12),
        'policy_changes':   (0.0,  0.1,  0, 1),
        'service_events':   (2.0,  1.5,  0, 7),
        'tcp_connections':  (200.0,50.0, 100, 400),
        'running_processes':(235.0,20.0, 150, 285),
    },
    'anomaly': {
        'failed_logins':    (2.0,  2.0,  0, 8),
        'success_logins':   (3.0,  2.0,  0, 10),
        'new_processes':    (20.0, 8.0,  8, 45),
        'policy_changes':   (2.0,  1.5,  0, 6),
        'service_events':   (5.0,  3.0,  1, 15),
        'tcp_connections':  (85.0, 25.0, 30, 150),
        'running_processes':(260.0,25.0, 200, 320),
    },
}


def _sample(mean, std, lo, hi) -> int:
    val = random.gauss(mean, std)
    return max(lo, min(hi, int(round(val))))


def generate_dataset(
    n_normal: int      = 300,
    n_brute_force: int = 150,
    n_port_scan: int   = 150,
    n_anomaly: int     = 150,
    save_to_db: bool   = True,
) -> list:
    """
    Belgilangan sonlar bo'yicha har bir label uchun namunalar yaratadi.
    save_to_db=True bo'lsa LogWindow yozuvlarini saqlaydi.
    Qaytaradi: list of dicts
    """
    from django.utils import timezone as dj_tz
    from lab.models import LogWindow

    plan = [
        ('normal',      n_normal),
        ('brute_force', n_brute_force),
        ('port_scan',   n_port_scan),
        ('anomaly',     n_anomaly),
    ]

    # Vaqtni 30 kun orqaga surib boshlаymiz, 5 daqiqalik oynalar
    base_time = dj_tz.now() - timedelta(days=30)
    minute_offset = 0
    rows = []

    for label, count in plan:
        dist = DISTRIBUTIONS[label]
        for _ in range(count):
            row = {
                'timestamp':         base_time + timedelta(minutes=minute_offset),
                'failed_logins':     _sample(*dist['failed_logins']),
                'success_logins':    _sample(*dist['success_logins']),
                'new_processes':     _sample(*dist['new_processes']),
                'policy_changes':    _sample(*dist['policy_changes']),
                'service_events':    _sample(*dist['service_events']),
                'tcp_connections':   _sample(*dist['tcp_connections']),
                'running_processes': _sample(*dist['running_processes']),
                'label':             label,
                'source':            'synthetic',
            }
            rows.append(row)
            minute_offset += 5

    # Vaqt bo'yicha aralashtiramiz (real scenario ga o'xshash)
    random.shuffle(rows)

    if save_to_db:
        objs = [LogWindow(**r) for r in rows]
        LogWindow.objects.bulk_create(objs, batch_size=200)
        logger.info("Dataset saqlandi: %d yozuv", len(objs))

    return rows


if __name__ == '__main__':
    import django, os, sys
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguard.settings')
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    django.setup()

    from lab.models import LogWindow
    before = LogWindow.objects.count()
    rows = generate_dataset()
    after = LogWindow.objects.count()

    print(f"\nDataset yaratildi: {after - before} yangi yozuv")
    print(f"Jami DB da: {after} ta LogWindow")
    from collections import Counter
    label_counts = Counter(r['label'] for r in rows)
    for label, cnt in sorted(label_counts.items()):
        print(f"  {label:15s}: {cnt}")
