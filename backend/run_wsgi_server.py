import os
from wsgiref.simple_server import make_server


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguard.settings')

from cyberguard.wsgi import application  # noqa: E402


def main():
    host = '127.0.0.1'
    port = 8000
    server = make_server(host, port, application)
    print(f'CyberGuard WSGI listening on http://{host}:{port}')
    server.serve_forever()


if __name__ == '__main__':
    main()
