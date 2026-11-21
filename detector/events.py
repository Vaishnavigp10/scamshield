"""Tiny event bus. Stages of the pipeline subscribe to named events.
- EVENT_ASYNC=0 -> handlers run inline (simple, deterministic)
- EVENT_ASYNC=1 -> handlers run on a background thread pool (queue-like behaviour)
- AWS_SQS_QUEUE_URL set -> every event is ALSO mirrored to Amazon SQS (cloud hook)."""
import json
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.db import connection

logger = logging.getLogger(__name__)
_handlers = defaultdict(list)
_pool = None


def subscribe(event_name):
    def deco(fn):
        _handlers[event_name].append(fn)
        return fn
    return deco


def _run(handler, payload, in_thread):
    try:
        handler(payload)
    except Exception:  # a failing stage must never crash ingestion
        logger.exception("handler %s failed", handler.__name__)
    finally:
        if in_thread:
            connection.close()


def _mirror_to_sqs(name, payload):
    if not settings.AWS_SQS_QUEUE_URL:
        return
    try:
        import boto3
        boto3.client("sqs", region_name=settings.AWS_REGION).send_message(
            QueueUrl=settings.AWS_SQS_QUEUE_URL,
            MessageBody=json.dumps({"event": name, **payload}),
        )
    except Exception:
        logger.exception("SQS mirror failed")


def publish(name, payload):
    global _pool
    _mirror_to_sqs(name, payload)
    for handler in _handlers[name]:
        if settings.EVENT_ASYNC:
            _pool = _pool or ThreadPoolExecutor(max_workers=2)
            _pool.submit(_run, handler, payload, True)
        else:
            _run(handler, payload, False)
