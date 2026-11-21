from django.apps import AppConfig


class DetectorConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "detector"

    def ready(self):
        from . import handlers  # noqa: F401  (registers pipeline subscribers)
