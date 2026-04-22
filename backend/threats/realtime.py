import asyncio
from collections import deque
from datetime import datetime, timezone
from threading import Lock


_RECENT_EVENTS = deque(maxlen=200)
_SUBSCRIBERS = set()
_LOCK = Lock()


def build_event(kind: str, payload: dict) -> dict:
    return {
        'kind': kind,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'payload': payload,
    }


def publish_event(kind: str, payload: dict):
    event = build_event(kind, payload)
    with _LOCK:
        _RECENT_EVENTS.append(event)
        subscribers = list(_SUBSCRIBERS)

    for queue in subscribers:
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            continue

    return event


def get_recent_events(limit: int = 30) -> list[dict]:
    with _LOCK:
        return list(_RECENT_EVENTS)[-limit:]


async def register_listener() -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue(maxsize=50)
    with _LOCK:
        _SUBSCRIBERS.add(queue)
    return queue


async def unregister_listener(queue: asyncio.Queue):
    with _LOCK:
        _SUBSCRIBERS.discard(queue)
