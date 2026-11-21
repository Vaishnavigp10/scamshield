# 🛡️ ScamShield — Scam & Phishing Detection Pipeline
Event-driven ingest of reported messages → AI classification → trends dashboard → public REST API (Django).

## Run locally
```bash
python -m venv venv && venv\Scripts\activate      # Windows  (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```
Open http://127.0.0.1:8000 · Dashboard `/dashboard/` · API docs `/api-docs/` · Tests: `python manage.py test`

## Pipeline
`report.received` → classify stage → `report.classified` → alert / campaign stage → dashboard + API.
Set `EVENT_ASYNC=1` for background processing, `AWS_SQS_QUEUE_URL` to mirror events to Amazon SQS.
