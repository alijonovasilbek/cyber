"""
Localhost ga hujum simulyatsiyasi.
Faqat O'Z mashinangizga ishlatiladi — akademik maqsad.

Simulyatsiya turlari:
  brute_force  — localhost ga ko'p marta noto'g'ri login urinish (SMB/RDP)
  port_scan    — localhost portlarini tekshirish
  anomaly      — g'ayrioddiy process va buyruqlar
"""

import socket
import subprocess
import threading
import time
import logging

logger = logging.getLogger(__name__)


# ── Brute Force Simulator ─────────────────────────────────────────────────

def simulate_brute_force(target: str = '127.0.0.1', attempts: int = 30, delay: float = 0.1):
    """
    Localhost ning 445 (SMB) yoki 3389 (RDP) portiga noto'g'ri
    ulanish urinishlari — Windows da 4625 event hosil qiladi.

    Haqiqiy parol sinab ko'rilmaydi — faqat port ulanishi va TCP reset.
    """
    ports = [445, 3389, 22, 23]
    success = 0
    failed  = 0

    logger.info("Brute force simulyatsiyasi boshlandi: %s, %d urinish", target, attempts)

    for i in range(attempts):
        port = ports[i % len(ports)]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                success += 1
            else:
                failed += 1
        except Exception:
            failed += 1
        time.sleep(delay)

    logger.info("Brute force tugadi: %d urinish (%d connect, %d fail)", attempts, success, failed)
    return {'attempts': attempts, 'connected': success, 'failed': failed}


# ── Port Scan Simulator ───────────────────────────────────────────────────

def simulate_port_scan(target: str = '127.0.0.1', port_range: tuple = (1, 1024), timeout: float = 0.15):
    """
    Localhost portlarini skanerlaydi.
    Windows Firewall bu urinishlarni loglaydi.
    """
    open_ports = []
    start, end = port_range

    logger.info("Port scan boshlandi: %s, portlar %d-%d", target, start, end)

    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass

    threads = []
    for port in range(start, end + 1):
        t = threading.Thread(target=check_port, args=(port,), daemon=True)
        threads.append(t)
        t.start()
        # 50 ta thread bilan cheklaymiz
        if len(threads) >= 50:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    logger.info("Port scan tugadi: %d ochiq port topildi", len(open_ports))
    return {'scanned': end - start + 1, 'open_ports': sorted(open_ports)}


# ── Anomaly Simulator ─────────────────────────────────────────────────────

def simulate_anomaly():
    """
    G'ayrioddiy process va buyruqlar — Windows 4688 event hosil qiladi.
    Faqat zararsiz sistema buyruqlari.
    """
    commands = [
        ['whoami'],
        ['ipconfig', '/all'],
        ['netstat', '-an'],
        ['tasklist'],
        ['net', 'user'],
        ['systeminfo'],
        ['arp', '-a'],
    ]

    results = []
    logger.info("Anomaly simulyatsiyasi boshlandi: %d buyruq", len(commands))

    for cmd in commands:
        try:
            out = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )
            results.append({'cmd': ' '.join(cmd), 'ok': True})
        except Exception as e:
            results.append({'cmd': ' '.join(cmd), 'ok': False, 'error': str(e)})
        time.sleep(0.2)

    logger.info("Anomaly tugadi: %d buyruq bajarildi", len(results))
    return {'commands_run': len(results), 'details': results}


# ── Asosiy funksiya ───────────────────────────────────────────────────────

def run_simulation(sim_type: str, **kwargs) -> dict:
    """
    sim_type: 'brute_force' | 'port_scan' | 'anomaly'
    """
    if sim_type == 'brute_force':
        return simulate_brute_force(
            attempts=kwargs.get('attempts', 30),
            delay=kwargs.get('delay', 0.1),
        )
    elif sim_type == 'port_scan':
        return simulate_port_scan(
            port_range=kwargs.get('port_range', (1, 512)),
            timeout=kwargs.get('timeout', 0.15),
        )
    elif sim_type == 'anomaly':
        return simulate_anomaly()
    else:
        raise ValueError(f"Noma'lum simulyatsiya turi: {sim_type}")


if __name__ == '__main__':
    import django, os, sys
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguard.settings')
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    django.setup()

    sim_type = sys.argv[1] if len(sys.argv) > 1 else 'port_scan'
    print(f"\n--- {sim_type.upper()} simulyatsiyasi ---")
    result = run_simulation(sim_type)
    print(result)

    # Simulyatsiyadan keyin log yig'amiz
    from lab.collector import collect_and_save
    label_map = {'brute_force': 'brute_force', 'port_scan': 'port_scan', 'anomaly': 'anomaly'}
    window, counts = collect_and_save(label=label_map.get(sim_type, 'anomaly'))
    print(f"\nLog saqlandi: {window}")
    for k, v in counts.items():
        print(f"  {k:20s} = {v}")
