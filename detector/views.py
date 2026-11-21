from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render

from .models import Report

SAMPLES = [
    ("Bank KYC", "Dear customer your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login"),
    ("Parcel fee", "Your parcel could not be delivered. Pay Rs 49 customs fee to reschedule http://india-post-track.click/pay"),
    ("Job offer", "Part time job work from home earn Rs 5000 per day. Message on Telegram now, limited seats"),
    ("Prize", "Congratulations! You won Rs 25,00,000 in the lucky draw. Pay a processing fee to claim your prize"),
    ("Genuine alert", "Your OTP for login is 482913. Do not share this OTP with anyone. Valid for 10 minutes."),
    ("Normal chat", "Hey, are we still meeting for lunch tomorrow at 1 pm?"),
]


def home(request):
    recent = Report.objects.filter(status="processed")[:6]
    return render(request, "detector/home.html", {"samples": SAMPLES, "recent": recent, "page": "home"})


def dashboard(request):
    return render(request, "detector/dashboard.html", {"page": "dashboard"})


def report_list(request):
    qs = Report.objects.filter(status="processed")
    label, category = request.GET.get("label", ""), request.GET.get("category", "")
    if label:
        qs = qs.filter(label=label)
    if category:
        qs = qs.filter(category=category)
    cats = Report.objects.exclude(category="").values_list("category", flat=True).distinct().order_by("category")
    page = Paginator(qs, 12).get_page(request.GET.get("page"))
    return render(request, "detector/reports.html", {
        "page_obj": page, "label": label, "category": category, "cats": cats, "page": "reports"})


def report_detail(request, pk):
    return render(request, "detector/report_detail.html", {"r": get_object_or_404(Report, pk=pk), "page": "reports"})


def architecture(request):
    return render(request, "detector/architecture.html", {"page": "architecture"})


def api_docs(request):
    return render(request, "detector/api_docs.html", {"page": "api"})
