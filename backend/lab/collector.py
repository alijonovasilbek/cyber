"""
Windows log collector — ikki manbadan o'qiydi:

1. Windows Event Log (win32evtlog) — admin huquq bo'lsa
   4625: Failed login, 4624: Success login
   4688: New process,  4719: Policy change, 7036: Service event

2. Fallback (har doim ishlaydi):
   - netstat: faol TCP ulanishlar soni
   - tasklist: ishayotgan processlar soni
   - wevtutil: Event log statistikasi
"""

import logging
import subprocess
import re
from datetime import datetime, timedelta
from collections import Counter

logger = logging.getLogger(__name__)

try:
    import win32evtlog
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


# ── Windows Event Log (admin talab qiladi) ───────────────────────────────

def _read_evtlog_win32(minutes: int) -> dict:
    from django.utils import timezone as dj_tz
    since = dj_tz.now() - timedelta(minutes=minutes)
    since_naive = since.replace(tzinfo=None) if since.tzinfo else since

    counts = Counter()
    mapping = {4625: 'failed_logins', 4624: 'success_logins',
               4688: 'new_processes', 4719: 'policy_changes', 7036: 'service_events'}

    for log_name in ('Security', 'System'):
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for ev in events:
                    pt = ev.TimeGenerated
                    ev_dt = datetime(pt.year, pt.month, pt.day, pt.hour, pt.minute, pt.second)
                    if ev_dt < since_naive:
                        break
                    key = mapping.get(ev.EventID & 0xFFFF)
                    if key:
                        counts[key] += 1
            win32evtlog.CloseEventLog(hand)
        except Exception as exc:
            logger.debug("win32evtlog (%s): %s", log_name, exc)

    return dict(counts)


# ── Fallback: netstat + tasklist ─────────────────────────────────────────

def _count_tcp_connections() -> int:
    """Hozirda ESTABLISHED TCP ulanishlar sonini qaytaradi."""
    try:
        out = subprocess.check_output(
            ['netstat', '-n', '-p', 'TCP'],
            text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        return out.count('ESTABLISHED')
    except Exception:
        return 0


def _count_processes() -> int:
    """Ishayotgan process sonini qaytaradi."""
    try:
        out = subprocess.check_output(
            ['tasklist', '/NH'],
            text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        return len([l for l in out.strip().splitlines() if l.strip()])
    except Exception:
        return 0


def _read_wevtutil_failed_logins(minutes: int) -> int:
    """wevtutil orqali oxirgi N daqiqadagi 4625 eventlar."""
    try:
        from django.utils import timezone as dj_tz
        since = dj_tz.now() - timedelta(minutes=minutes)
        since_str = since.strftime('%Y-%m-%dT%H:%M:%S')
        query = f"*[System[(EventID=4625) and TimeCreated[@SystemTime>='{since_str}']]]"
        out = subprocess.check_output(
            ['wevtutil', 'qe', 'Security', f'/q:{query}', '/c:500', '/f:text'],
            text=True, timeout=10, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        return out.count('Event[')
    except Exception:
        return 0


def _read_wevtutil_processes(minutes: int) -> int:
    """wevtutil orqali oxirgi N daqiqadagi 4688 eventlar."""
    try:
        from django.utils import timezone as dj_tz
        since = dj_tz.now() - timedelta(minutes=minutes)
        since_str = since.strftime('%Y-%m-%dT%H:%M:%S')
        query = f"*[System[(EventID=4688) and TimeCreated[@SystemTime>='{since_str}']]]"
        out = subprocess.check_output(
            ['wevtutil', 'qe', 'Security', f'/q:{query}', '/c:500', '/f:text'],
            text=True, timeout=10, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
        )
        return out.count('Event[')
    except Exception:
        return 0


# ── Asosiy funksiya ───────────────────────────────────────────────────────

def read_event_counts(minutes: int = 5) -> dict:
    """
    Oxirgi `minutes` daqiqadagi Windows xavfsizlik ko'rsatkichlarini
    qaytaradi. Win32 API → wevtutil → netstat/tasklist ketma-ketlikda urinadi.
    """
    counts = {
        'failed_logins':  0,
        'success_logins': 0,
        'new_processes':  0,
        'policy_changes': 0,
        'service_events': 0,
        'tcp_connections': _count_tcp_connections(),
        'running_processes': _count_processes(),
    }

    if HAS_WIN32:
        win32_counts = _read_evtlog_win32(minutes)
        counts.update({k: win32_counts.get(k, 0) for k in
                       ('failed_logins', 'success_logins', 'new_processes',
                        'policy_changes', 'service_events')})
    else:
        # wevtutil fallback
        counts['failed_logins'] = _read_wevtutil_failed_logins(minutes)
        counts['new_processes']  = _read_wevtutil_processes(minutes)

    return counts


def collect_and_save(label: str = 'normal', minutes: int = 5):
    """
    Hozirgi vaqtdan `minutes` daqiqa oldingi loglarni o'qib
    yangi LogWindow yozuvi yaratadi va qaytaradi.
    """
    from lab.models import LogWindow
    from django.utils import timezone as dj_tz

    counts = read_event_counts(minutes=minutes)
    window = LogWindow.objects.create(
        timestamp          = dj_tz.now(),
        failed_logins      = counts['failed_logins'],
        success_logins     = counts['success_logins'],
        new_processes      = counts['new_processes'],
        policy_changes     = counts['policy_changes'],
        service_events     = counts['service_events'],
        tcp_connections    = counts['tcp_connections'],
        running_processes  = counts['running_processes'],
        label              = label,
        source             = 'collector',
    )
    logger.info("LogWindow saqlandi: %s", window)
    return window, counts


if __name__ == '__main__':
    import django, os, sys
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguard.settings')
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    django.setup()

    window, counts = collect_and_save(label='normal')
    print(f"\nSaqlandi: {window}")
    for k, v in counts.items():
        print(f"  {k:20s} = {v}")
