import asyncio
import json
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguard.settings')

from django.conf import settings
from django.core.asgi import get_asgi_application

django_asgi_app = get_asgi_application()

from threats.realtime import get_recent_events, register_listener, unregister_listener  # noqa: E402


async def websocket_live(scope, receive, send):
    await send({'type': 'websocket.accept'})
    for event in get_recent_events(getattr(settings, 'WEBSOCKET_RECENT_EVENT_LIMIT', 25)):
        await send({'type': 'websocket.send', 'text': json.dumps(event)})

    queue = await register_listener()
    pending_receive = None
    pending_queue = None
    try:
        while True:
            pending_receive = asyncio.create_task(receive())
            pending_queue = asyncio.create_task(queue.get())
            done, pending = await asyncio.wait(
                {pending_receive, pending_queue},
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            if pending_receive in done:
                message = pending_receive.result()
                if message['type'] == 'websocket.disconnect':
                    break
                if message['type'] == 'websocket.receive':
                    await send({
                        'type': 'websocket.send',
                        'text': json.dumps({'kind': 'heartbeat', 'payload': 'connected'}),
                    })

            if pending_queue in done:
                event = pending_queue.result()
                await send({'type': 'websocket.send', 'text': json.dumps(event)})
    finally:
        if pending_receive:
            pending_receive.cancel()
        if pending_queue:
            pending_queue.cancel()
        await unregister_listener(queue)


async def application(scope, receive, send):
    if scope['type'] == 'websocket' and scope.get('path') == '/ws/live':
        await websocket_live(scope, receive, send)
        return
    await django_asgi_app(scope, receive, send)
