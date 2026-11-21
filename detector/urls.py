from django.urls import path

from . import api, views

urlpatterns = [
    path("", views.home, name="home"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("reports/", views.report_list, name="reports"),
    path("reports/<uuid:pk>/", views.report_detail, name="report_detail"),
    path("architecture/", views.architecture, name="architecture"),
    path("api-docs/", views.api_docs, name="api_docs"),
    # public API
    path("api/v1/health/", api.health),
    path("api/v1/check/", api.check),
    path("api/v1/reports/", api.reports),
    path("api/v1/reports/<uuid:pk>/", api.report_detail),
    path("api/v1/stats/", api.stats),
]
