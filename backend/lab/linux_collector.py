"""
Linux/Docker muhitida victim container auth.log ni o'quvchi collector.
Windows collector bilan birga ishlatiladi (platform ga qarab tanlanadi).
"""
import os
import re
import subprocess
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

VICTIM_LOG_FILE = os.environ.get('VICTIM_LOG_FILE', '/victim-logs/auth.log')

_FAILED_RE  = re.compile(r'Failed password')
_SUCCESS_RE = re.compile(r'Accepted password')
_TS_RE      = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')


def _parse_ts(line: str, year: int) -> datetime | None:
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        return datetime.strptime(f"{m.group(1)} {year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def read_victim_auth_log(minutes: int = 5) -> dict:
    counts = {
        'failed_logins':  0,
        'success_logins': 0,
        'new_processes':  0,
        'policy_changes': 0,
        'service_events': 0,
    }
    if not os.path.exists(VICTIM_LOG_FILE):
        logger.debug("Victim auth.log topilmadi: %s", VICTIM_LOG_FILE)
        return counts

    # Read last N lines — timestamp filtering is unreliable due to timezone
    # differences between victim/backend containers. Attacker calls auto-collect
    # immediately after each attack phase, so recent lines == current window.
    lines_to_read = max(300, minutes * 60)
    try:
        with open(VICTIM_LOG_FILE, 'r', errors='replace') as f:
            all_lines = f.readlines()
        recent = all_lines[-lines_to_read:]
        for line in recent:
            if _FAILED_RE.search(line):
                counts['failed_logins'] += 1
            elif _SUCCESS_RE.search(line):
                counts['success_logins'] += 1
    except Exception as e:
        logger.warning("Auth log o'qishda xato: %s", e)
    return counts


def _count_tcp() -> int:
    try:
        r = subprocess.run(
            ['ss', '-tn', 'state', 'established'],
            capture_output=True, text=True, timeout=5,
        )
        return max(0, len(r.stdout.strip().splitlines()) - 1)
    except Exception:
        try:
            r = subprocess.run(
                ['netstat', '-tn'],
                capture_output=True, text=True, timeout=5,
            )
            return r.stdout.count('ESTABLISHED')
        except Exception:
            return 0


def _count_processes() -> int:
    try:
        r = subprocess.run(
            ['ps', 'ax', '--no-headers'],
            capture_output=True, text=True, timeout=5,
        )
        return len(r.stdout.strip().splitlines())
    except Exception:
        return 0


def auto_label(counts: dict) -> str:
    """Feature qiymatlariga qarab avtomatik label aniqlash."""
    failed = counts.get('failed_logins', 0)
    tcp    = counts.get('tcp_connections', 0)
    procs  = counts.get('new_processes', 0)
    if failed >= 15:
        return 'brute_force'
    if tcp >= 150:
        return 'port_scan'
    if procs >= 12:
        return 'anomaly'
    return 'normal'


def collect_and_save_linux(label: str = 'auto', minutes: int = 5):
    """
    Victim auth.log + backend tizim ma'lumotlarini o'qib LogWindow yaratadi.
    label='auto' bo'lsa, feature qiymatlariga qarab avtomatik aniqlanadi.
    """
    from lab.models import LogWindow
    from django.utils import timezone as dj_tz

    auth  = read_victim_auth_log(minutes=minutes)
    tcp   = _count_tcp()
    procs = _count_processes()

    counts = {**auth, 'tcp_connections': tcp, 'running_processes': procs}

    if label == 'auto':
        label = auto_label(counts)

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
        source             = 'linux_collector',
    )
    logger.info("Linux LogWindow: %s | failed=%d tcp=%d label=%s",
                window.timestamp.strftime('%H:%M'), counts['failed_logins'],
                tcp, label)
    return window, counts


def read_recent_log_lines(n: int = 50) -> list:
    """Auth.log dan oxirgi n ta qatorni qaytaradi."""
    if not os.path.exists(VICTIM_LOG_FILE):
        return []
    try:
        with open(VICTIM_LOG_FILE, 'r', errors='replace') as f:
            lines = f.readlines()
        return [ln.rstrip() for ln in lines[-n:]]
    except Exception as e:
        logger.warning("Log o'qishda xato: %s", e)
        return []


def victim_status() -> dict:
    """Victim container holati."""
    log_exists = os.path.exists(VICTIM_LOG_FILE)
    last_modified = None
    line_count = 0
    recent_failed = 0

    if log_exists:
        try:
            mtime = os.path.getmtime(VICTIM_LOG_FILE)
            last_modified = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            with open(VICTIM_LOG_FILE, 'r', errors='replace') as f:
                lines = f.readlines()
            line_count = len(lines)
            recent_failed = sum(1 for ln in lines[-100:] if _FAILED_RE.search(ln))
        except Exception:
            pass

    return {
        'log_file':      VICTIM_LOG_FILE,
        'log_exists':    log_exists,
        'last_modified': last_modified,
        'total_lines':   line_count,
        'recent_failed': recent_failed,
        'online':        log_exists and line_count > 0,
    }
