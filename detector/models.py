import uuid
from django.db import models
from django.utils import timezone


class Report(models.Model):
    class Label(models.TextChoices):
        SAFE = "safe", "Safe"
        SUSPICIOUS = "suspicious", "Suspicious"
        SCAM = "scam", "Scam"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        PROCESSED = "processed", "Processed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    text = models.TextField()                      # stored REDACTED (no phones / emails / OTPs)
    channel = models.CharField(max_length=20, default="sms")
    sender = models.CharField(max_length=80, blank=True)
    source = models.CharField(max_length=10, default="web")
    text_hash = models.CharField(max_length=64, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    status = models.CharField(max_length=12, choices=Status.choices, default=Status.QUEUED)
    score = models.FloatField(null=True, blank=True)
    label = models.CharField(max_length=12, choices=Label.choices, blank=True, db_index=True)
    category = models.CharField(max_length=40, blank=True, db_index=True)
    reasons = models.JSONField(default=list, blank=True)
    urls = models.JSONField(default=list, blank=True)
    domains = models.JSONField(default=list, blank=True)
    campaign_size = models.PositiveIntegerField(default=1)
    processing_ms = models.PositiveIntegerField(null=True, blank=True)
    model_version = models.CharField(max_length=40, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.label or 'pending'}: {self.text[:50]}"


class PipelineEvent(models.Model):
    """Audit log of every event that flows through the pipeline."""

    name = models.CharField(max_length=40, db_index=True)
    report = models.ForeignKey(Report, null=True, blank=True, on_delete=models.CASCADE, related_name="events")
    detail = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["created_at", "id"]
