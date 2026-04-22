from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response


def get_client_ip(request) -> str:
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', 'unknown')


def verify_api_key(request):
    expected = getattr(settings, 'CYBERGUARD_API_KEY', '').strip()
    if not expected:
        return None

    supplied = (
        request.headers.get('X-API-Key')
        or request.META.get('HTTP_X_API_KEY')
        or request.query_params.get('api_key')
    )
    if supplied == expected:
        return None

    return Response(
        {'detail': 'Yaroqsiz yoki yetishmayotgan API key.'},
        status=status.HTTP_401_UNAUTHORIZED,
    )


def check_rate_limit(request, scope: str):
    limit = getattr(settings, 'SAFE_RATE_LIMIT_REQUESTS', 60)
    window = getattr(settings, 'SAFE_RATE_LIMIT_WINDOW', 60)
    client_ip = get_client_ip(request)
    cache_key = f'rate:{scope}:{client_ip}'
    current = cache.get(cache_key, 0)

    if current >= limit:
        return Response(
            {
                'detail': 'Rate limit oshib ketdi.',
                'scope': scope,
                'limit': limit,
                'window_seconds': window,
            },
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    cache.set(cache_key, current + 1, timeout=window)
    return None


def guard_request(request, scope: str):
    api_error = verify_api_key(request)
    if api_error:
        return api_error
    return check_rate_limit(request, scope)
