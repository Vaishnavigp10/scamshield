"""Public JSON API  (/api/v1/...)  - no key required, rate-limited per IP."""
import json
from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from . import classifier, services
from .models import Report


def _ip(request):
    fwd = request.META.get("HTTP_X_FORWARDED_FOR")
    return fwd.split(",")[0].strip() if fwd else request.META.get("REMOTE_ADDR", "?")


def endpoint(methods):
    def deco(fn):
        @wraps(fn)
        def wrapper(request, *a, **kw):
            if request.method == "OPTIONS":
                return JsonResponse({}, status=204)
            if request.method not in methods:
                return JsonResponse({"error": "method_not_allowed"}, status=405)
            key = f"rl:{_ip(request)}:{timezone.now().strftime('%Y%m%d%H%M')}"
            cache.add(key, 0, 70)
            if cache.incr(key) > settings.API_RATE_LIMIT_PER_MIN:
                return JsonResponse({"error": "rate_limited", "detail": "Too many requests, slow down."}, status=429)
            return fn(request, *a, **kw)
        return csrf_exempt(wrapper)
    return deco


def _body(request):
    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return None, JsonResponse({"error": "invalid_json"}, status=400)
    text = data.get("text")
    if not isinstance(text, str) or not (8 <= len(text.strip()) <= 2000):
        return None, JsonResponse({"error": "invalid_text", "detail": "'text' must be 8-2000 characters."}, status=400)
    return data, None


def serialize(r, full=True):
    d = {
        "id": str(r.id), "created_at": r.created_at.isoformat(), "status": r.status,
        "channel": r.channel, "label": r.label or None,
        "score": round(r.score, 3) if r.score is not None else None,
        "category": r.category or None, "campaign_size": r.campaign_size,
    }
    if full:
        d.update({
            "text": r.text, "reasons": r.reasons, "urls": r.urls, "domains": r.domains,
            "processing_ms": r.processing_ms, "model_version": r.model_version,
            "pipeline": [{"event": e.name, "detail": e.detail} for e in r.events.all()],
        })
    else:
        d["text_preview"] = r.text[:140]
    return d


@endpoint(["GET"])
def health(request):
    return JsonResponse({"status": "ok", "model": classifier.MODEL_VERSION, "time": timezone.now().isoformat()})


@endpoint(["POST"])
def check(request):
    """Stateless check - classifies but does NOT store the message."""
    data, err = _body(request)
    if err:
        return err
    clean = classifier.redact(data["text"])
    return JsonResponse({**classifier.classify(clean), "stored": False})


@endpoint(["GET", "POST"])
def reports(request):
    if request.method == "POST":
        data, err = _body(request)
        if err:
            return err
        r = services.ingest(data["text"], data.get("channel", "sms"), data.get("sender", ""), source="api")
        r.refresh_from_db()
        return JsonResponse(serialize(r), status=201)
    qs = Report.objects.filter(status=Report.Status.PROCESSED)
    for field in ("label", "category", "channel"):
        if request.GET.get(field):
            qs = qs.filter(**{field: request.GET[field]})
    try:
        limit = min(max(int(request.GET.get("limit", 20)), 1), 100)
        offset = max(int(request.GET.get("offset", 0)), 0)
    except ValueError:
        limit, offset = 20, 0
    total = qs.count()
    return JsonResponse({"count": total, "limit": limit, "offset": offset,
                         "results": [serialize(r, full=False) for r in qs[offset:offset + limit]]})


@endpoint(["GET"])
def report_detail(request, pk):
    return JsonResponse(serialize(get_object_or_404(Report, pk=pk)))


@endpoint(["GET"])
def stats(request):
    return JsonResponse(services.build_stats())
