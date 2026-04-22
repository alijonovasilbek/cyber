import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = 'django-insecure-cyberguard-bmi-demo-key-change-in-production'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_spectacular',
    'corsheaders',
    'threats',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

ROOT_URLCONF = 'cyberguard.urls'
ASGI_APPLICATION = 'cyberguard.asgi.application'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [], 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages']}}]

if os.environ.get('POSTGRES_DB'):
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('POSTGRES_DB'),
            'USER': os.environ.get('POSTGRES_USER', 'postgres'),
            'PASSWORD': os.environ.get('POSTGRES_PASSWORD', ''),
            'HOST': os.environ.get('POSTGRES_HOST', '127.0.0.1'),
            'PORT': os.environ.get('POSTGRES_PORT', '5432'),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.AllowAny'],
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'cyberguard-safe-cache',
    }
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'CyberGuard API',
    'DESCRIPTION': 'CyberGuard demo backend API documentation.',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
}

CORS_ALLOW_ALL_ORIGINS = True

STATIC_URL = '/static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# AbuseIPDB API (bepul ro'yxatdan o'tib oling: abuseipdb.com)
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', 'YOUR_API_KEY_HERE')
CYBERGUARD_API_KEY = os.environ.get('CYBERGUARD_API_KEY', 'cyberguard-demo-key')
SAFE_RATE_LIMIT_REQUESTS = int(os.environ.get('SAFE_RATE_LIMIT_REQUESTS', '60'))
SAFE_RATE_LIMIT_WINDOW = int(os.environ.get('SAFE_RATE_LIMIT_WINDOW', '60'))
SAFE_SCAN_CACHE_TTL = int(os.environ.get('SAFE_SCAN_CACHE_TTL', '120'))
THREAT_INTEL_CACHE_TTL = int(os.environ.get('THREAT_INTEL_CACHE_TTL', '900'))
WEBSOCKET_RECENT_EVENT_LIMIT = int(os.environ.get('WEBSOCKET_RECENT_EVENT_LIMIT', '25'))

# Demo local IP lar — real tarmoqdagi qurilmalar
LOCAL_DEMO_IPS = {
    '192.168.1.1':   {'name': 'Router/Gateway',      'risk': 'low',      'mac': 'AA:BB:CC:DD:EE:01'},
    '192.168.1.100': {'name': 'Admin PC',             'risk': 'low',      'mac': 'AA:BB:CC:DD:EE:02'},
    '192.168.1.101': {'name': 'Developer PC',         'risk': 'low',      'mac': 'AA:BB:CC:DD:EE:03'},
    '192.168.1.200': {'name': 'Shubhali qurilma',     'risk': 'high',     'mac': 'AA:BB:CC:DD:EE:04'},
    '192.168.1.201': {'name': 'Noma\'lum qurilma',    'risk': 'critical', 'mac': 'AA:BB:CC:DD:EE:05'},
    '10.0.0.1':      {'name': 'Core Switch',          'risk': 'low',      'mac': 'BB:CC:DD:EE:FF:01'},
    '10.0.0.10':     {'name': 'Web Server',           'risk': 'medium',   'mac': 'BB:CC:DD:EE:FF:02'},
    '10.0.0.20':     {'name': 'Database Server',      'risk': 'medium',   'mac': 'BB:CC:DD:EE:FF:03'},
    '172.16.0.1':    {'name': 'VPN Gateway',          'risk': 'low',      'mac': 'CC:DD:EE:FF:AA:01'},
    '172.16.0.50':   {'name': 'Test Server',          'risk': 'medium',   'mac': 'CC:DD:EE:FF:AA:02'},
}
