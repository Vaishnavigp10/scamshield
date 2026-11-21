import json
from django.test import TestCase
from . import classifier
from .models import Report


class ClassifierTests(TestCase):
    def test_scam_detected(self):
        r = classifier.classify("Dear customer your SBI account will be blocked today. Update KYC at http://sbi-kyc-update.xyz")
        self.assertEqual(r["label"], "scam")

    def test_legit_safe(self):
        self.assertEqual(classifier.classify("Hey, are we still meeting for lunch tomorrow at 1 pm?")["label"], "safe")

    def test_redaction(self):
        out = classifier.redact("Call 9876543210 or mail a@b.com, OTP is 482913")
        self.assertNotIn("9876543210", out); self.assertNotIn("a@b.com", out); self.assertNotIn("482913", out)


class ApiTests(TestCase):
    def test_submit_and_fetch(self):
        res = self.client.post("/api/v1/reports/", json.dumps({"text": "You won a lottery! Pay processing fee http://bit.ly/x to claim"}),
                               content_type="application/json")
        self.assertEqual(res.status_code, 201)
        d = res.json(); self.assertEqual(d["status"], "processed")
        self.assertIn("report.classified", [p["event"] for p in d["pipeline"]])
        self.assertEqual(self.client.get(f"/api/v1/reports/{d['id']}/").status_code, 200)
        self.assertEqual(Report.objects.count(), 1)

    def test_validation_and_stats(self):
        self.assertEqual(self.client.post("/api/v1/reports/", "{}", content_type="application/json").status_code, 400)
        self.assertEqual(self.client.get("/api/v1/stats/").status_code, 200)

    def test_pages(self):
        for url in ["/", "/dashboard/", "/reports/", "/architecture/", "/api-docs/"]:
            self.assertEqual(self.client.get(url).status_code, 200, url)
