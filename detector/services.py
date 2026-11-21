import time
from collections import Counter, defaultdict
from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from . import classifier, events
from .models import PipelineEvent, Report

CHANNELS = ["sms", "email", "whatsapp", "call", "social", "other"]


def log_event(name, report=None, detail=""):
    return PipelineEvent.objects.create(name=name, report=report, detail=detail[:200])


def ingest(text, channel="sms", sender="", source="web", created_at=None, emit=True):
    """Stage 1 - INGEST: sanitise, fingerprint, store as QUEUED and publish 'report.received'."""
    channel = channel if channel in CHANNELS else "other"
    clean = classifier.redact(text.strip())[:2000]
    report = Report.objects.create(
        text=clean, channel=channel, sender=classifier.redact(sender)[:80], source=source,
        text_hash=classifier.fingerprint(clean), **({"created_at": created_at} if created_at else {}),
    )
    log_event("report.received", report, f"via {source}/{channel}")
    if emit:
        events.publish("report.received", {"report_id": str(report.id)})
    return report


def process_report(report_id):
    """Stage 2 - CLASSIFY: run the model, persist the verdict, publish 'report.classified'."""
    report = Report.objects.get(pk=report_id)
    t0 = time.perf_counter()
    result = classifier.classify(report.text)
    report.score, report.label, report.category = result["score"], result["label"], result["category"]
    report.reasons, report.urls, report.domains = result["reasons"], result["urls"], result["domains"]
    report.model_version = result["model_version"]
    report.campaign_size = Report.objects.filter(text_hash=report.text_hash).count()
    report.processing_ms = int((time.perf_counter() - t0) * 1000)
    report.status = Report.Status.PROCESSED
    report.save()
    log_event("report.classified", report, f"{report.label} ({report.score:.2f}) - {report.category}")
    return report


def build_stats(days=14):
    now = timezone.now()
    since = now - timedelta(days=days - 1)
    qs = Report.objects.filter(status=Report.Status.PROCESSED)
    total = qs.count()
    by_label = {r["label"]: r["n"] for r in qs.values("label").annotate(n=Count("id")).values("label", "n")}
    scam, susp, safe = by_label.get("scam", 0), by_label.get("suspicious", 0), by_label.get("safe", 0)

    # daily trend
    rows = (qs.filter(created_at__gte=since.replace(hour=0, minute=0, second=0, microsecond=0))
            .annotate(d=TruncDate("created_at")).values("d", "label").annotate(n=Count("id")))
    grid = defaultdict(lambda: {"scam": 0, "suspicious": 0, "safe": 0})
    for r in rows:
        grid[r["d"]][r["label"]] = r["n"]
    labels, series = [], {"scam": [], "suspicious": [], "safe": []}
    local_today = timezone.localdate()
    for i in range(days - 1, -1, -1):
        d = local_today - timedelta(days=i)
        labels.append(d.strftime("%d %b"))
        for k in series:
            series[k].append(grid[d][k])

    cats = qs.exclude(label="safe").values("category").annotate(n=Count("id")).order_by("-n")[:8]
    chans = qs.values("channel").annotate(n=Count("id")).order_by("-n")

    dom = Counter()
    for doms in qs.exclude(label="safe").order_by("-created_at").values_list("domains", flat=True)[:600]:
        dom.update(doms)

    camp = (qs.exclude(label="safe").values("text_hash").annotate(n=Count("id")).filter(n__gte=3).order_by("-n")[:5])
    campaigns = []
    for c in camp:
        sample = qs.filter(text_hash=c["text_hash"]).first()
        campaigns.append({"count": c["n"], "text": sample.text[:110], "category": sample.category})

    avg_ms = qs.exclude(processing_ms=None).values_list("processing_ms", flat=True)[:500]
    last24 = qs.filter(created_at__gte=now - timedelta(hours=24)).count()
    recent_events = [
        {"name": e.name, "detail": e.detail, "at": timezone.localtime(e.created_at).strftime("%H:%M:%S")}
        for e in PipelineEvent.objects.order_by("-created_at", "-id")[:10]
    ]
    return {
        "kpis": {
            "total": total, "scam": scam, "suspicious": susp, "safe": safe,
            "scam_rate": round(100 * (scam + susp) / total, 1) if total else 0,
            "last24h": last24, "campaigns": len(campaigns),
            "avg_ms": round(sum(avg_ms) / len(avg_ms), 1) if avg_ms else 0,
        },
        "daily": {"labels": labels, **series},
        "categories": [{"name": c["category"], "count": c["n"]} for c in cats],
        "channels": [{"name": c["channel"], "count": c["n"]} for c in chans],
        "top_domains": [{"domain": d, "count": n} for d, n in dom.most_common(8)],
        "campaigns": campaigns,
        "events": recent_events,
        "generated_at": timezone.localtime(now).strftime("%d %b %Y %H:%M:%S"),
    }
