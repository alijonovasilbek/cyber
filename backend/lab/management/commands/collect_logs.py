"""
Django management command: avtomatik log yig'ish.

Ishlatish:
  python manage.py collect_logs             # bir marta
  python manage.py collect_logs --loop      # har 5 daqiqada
  python manage.py collect_logs --label brute_force  # belgilangan label bilan

Windows Task Scheduler yoki buyruq satri orqali ishlating.
"""

import time
import logging
from django.core.management.base import BaseCommand
from lab.collector import collect_and_save

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Windows Event Log lardan LogWindow yig\'ib DBga saqlaydi'

    def add_arguments(self, parser):
        parser.add_argument('--loop',    action='store_true', help='Har 5 daqiqada qaytadan ishga tushiradi')
        parser.add_argument('--interval',type=int, default=300, help='Loop intervali (soniya, default: 300)')
        parser.add_argument('--label',   type=str, default='normal',
                            choices=['normal', 'brute_force', 'port_scan', 'anomaly'],
                            help='Yozuvga qo\'yiladigan label')

    def handle(self, *args, **options):
        loop     = options['loop']
        interval = options['interval']
        label    = options['label']

        self.stdout.write(self.style.SUCCESS(
            f'Log collector ishga tushdi | label={label} | loop={loop}'
        ))

        if loop:
            self.stdout.write(f'Har {interval} soniyada yig\'iladi. To\'xtatish: Ctrl+C\n')
            count = 0
            while True:
                try:
                    window, counts = collect_and_save(label=label)
                    count += 1
                    self.stdout.write(
                        f'[{count}] {window.timestamp:%H:%M:%S} | {label} | '
                        f'fails={counts["failed_logins"]} '
                        f'tcp={counts["tcp_connections"]} '
                        f'procs={counts["running_processes"]}'
                    )
                except KeyboardInterrupt:
                    self.stdout.write('\nTo\'xtatildi.')
                    break
                except Exception as e:
                    self.stderr.write(f'Xato: {e}')
                time.sleep(interval)
        else:
            window, counts = collect_and_save(label=label)
            self.stdout.write(self.style.SUCCESS(
                f'Saqlandi: ID={window.pk} | {window.timestamp:%Y-%m-%d %H:%M:%S}'
            ))
            for k, v in counts.items():
                self.stdout.write(f'  {k:20s} = {v}')
