"""Pipeline subscribers (the 'serverless functions' of this project)."""
from . import events, services
from .models import Report


@events.subscribe("report.received")
def classify_stage(payload):
    report = services.process_report(payload["report_id"])
    events.publish("report.classified", {"report_id": str(report.id)})


@events.subscribe("report.classified")
def alert_stage(payload):
    report = Report.objects.get(pk=payload["report_id"])
    if report.label == "scam" and (report.score or 0) >= 0.85:
        services.log_event("alert.high_risk", report, f"High-risk {report.category} message")
    if report.label != "safe" and report.campaign_size >= 3:
        services.log_event("campaign.detected", report, f"{report.campaign_size} similar reports")
