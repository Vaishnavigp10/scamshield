import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from detector import services
from detector.models import PipelineEvent, Report

BRANDS = ["SBI", "HDFC", "ICICI", "Axis Bank", "Paytm", "Amazon", "Netflix"]
SCAM_T = [
    ("Dear customer your {b} account will be blocked today. Update KYC immediately at http://{d}/kyc", True),
    ("URGENT: {b} net banking suspended. Verify your PAN and Aadhaar now http://{d}/verify", False),
    ("Congratulations! You have won Rs {n},00,000 in the lucky draw. Pay processing fee to claim your prize", True),
    ("Your parcel could not be delivered. Pay Rs {m} customs fee to reschedule http://{d}/pay", False),
    ("Part time job work from home earn Rs {m}0 per day. Join our Telegram group today", True),
    ("Guaranteed 300% returns on crypto investment in 7 days. Join our VIP trading group now", True),
    ("Your electricity will be disconnected tonight because last month bill is not updated. Call officer immediately", True),
    ("Income Tax refund of Rs {n},480 approved. Submit bank details at http://{d}/refund to receive", False),
    ("Security alert: unusual sign in to your {b} account. Verify your password http://{d}/login", False),
    ("Share the OTP you received to complete refund of your failed transaction", True),
    ("Microsoft Support: your computer is infected with a virus. Call toll free number immediately", False),
    ("Hi mum my phone is broken this is my new number. Please send Rs {n}000 urgently", False),
]
LEGIT_T = [
    "Your OTP for login is {n}1234. Do not share this OTP with anyone. Valid for 10 minutes.",
    "Your Swiggy order has been delivered. Rate your experience in the app.",
    "Hi, are we still meeting for lunch tomorrow at {m} pm? Let me know.",
    "Your Amazon order has shipped and will arrive on Thursday. Track in the app.",
    "Assignment {n} has been uploaded to the LMS. Deadline is Friday 11:59 PM.",
    "Rs {m}.00 debited from A/c XX4521 at Big Bazaar. If not you, call the number on your card.",
    "Your Uber ride is arriving in 3 minutes.",
]
DOMAINS = ["kyc-update", "secure-verify", "india-post-track", "refund-portal", "acc-login-help", "claim-reward"]
TLDS = ["xyz", "top", "click", "icu", "online"]
CHANNELS = ["sms"] * 5 + ["whatsapp"] * 3 + ["email"] * 3 + ["call", "social"]


class Command(BaseCommand):
    help = "Create realistic demo reports so the dashboard has data."

    def add_arguments(self, p):
        p.add_argument("--count", type=int, default=260)
        p.add_argument("--if-empty", action="store_true")
        p.add_argument("--reset", action="store_true")

    def handle(self, *a, **o):
        if o["reset"]:
            Report.objects.all().delete(); PipelineEvent.objects.all().delete()
        if o["if_empty"] and Report.objects.exists():
            return self.stdout.write("Data exists - skipping seed.")
        rnd, now = random.Random(7), timezone.now()
        fixed = {i: f"{rnd.choice(DOMAINS)}.{rnd.choice(TLDS)}" for i in range(len(SCAM_T))}
        for _ in range(o["count"]):
            age = min(13, int(rnd.expovariate(0.22)))             # more recent reports than old ones
            when = now - timedelta(days=age, minutes=rnd.randint(0, 1400))
            if rnd.random() < 0.68:
                i = rnd.randrange(len(SCAM_T)); tpl, campaign = SCAM_T[i]
                dom = fixed[i] if campaign else f"{rnd.choice(DOMAINS)}-{rnd.randint(1,99)}.{rnd.choice(TLDS)}"
                text = tpl.format(b=rnd.choice(BRANDS), d=dom, n=rnd.randint(5, 50), m=rnd.randint(20, 90))
            else:
                text = rnd.choice(LEGIT_T).format(n=rnd.randint(1, 9), m=rnd.randint(1, 12) * 100)
            r = services.ingest(text, rnd.choice(CHANNELS), source="seed", created_at=when, emit=False)
            services.process_report(r.id)
        PipelineEvent.objects.filter(report__source="seed").update(created_at=now - timedelta(days=1))
        self.stdout.write(self.style.SUCCESS(f"Seeded {o['count']} reports."))
