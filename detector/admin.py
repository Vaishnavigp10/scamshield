from django.contrib import admin
from .models import PipelineEvent, Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("created_at", "label", "category", "score", "channel", "campaign_size")
    list_filter = ("label", "category", "channel", "source")
    search_fields = ("text",)


admin.site.register(PipelineEvent)
