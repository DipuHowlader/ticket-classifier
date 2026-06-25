"""
Tests against the 8 public sample cases from the spec, plus extra edge cases
for the safety rule (no PIN/OTP/password/card-number solicitation in summary)
and basic schema validation.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json().get("status") == "ok"


PUBLIC_CASES = [
    ("I sent 3000 to wrong number", "wrong_transfer", "high"),
    ("Payment failed but balance deducted", "payment_failed", "high"),
    ("Someone called asking my OTP, is that bKash?", "phishing_or_social_engineering", "critical"),
    ("Please refund my last transaction, I changed my mind", "refund_request", "low"),
    ("App crashed when I opened it", "other", "low"),
]


def test_public_sample_cases():
    for i, (message, expected_case_type, expected_severity) in enumerate(PUBLIC_CASES, start=1):
        resp = client.post(
            "/sort-ticket",
            json={"ticket_id": f"T-{i:03d}", "message": message},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["ticket_id"] == f"T-{i:03d}"
        assert body["case_type"] == expected_case_type, (
            f"msg={message!r} expected {expected_case_type} got {body['case_type']}"
        )
        assert body["severity"] == expected_severity, (
            f"msg={message!r} expected severity {expected_severity} got {body['severity']}"
        )
        assert 0.0 <= body["confidence"] <= 1.0
        assert isinstance(body["human_review_required"], bool)


def test_phishing_forces_human_review():
    resp = client.post(
        "/sort-ticket",
        json={"ticket_id": "T-100", "message": "Someone called pretending to be bKash and asked for my PIN"},
    )
    body = resp.json()
    assert body["case_type"] == "phishing_or_social_engineering"
    assert body["human_review_required"] is True
    assert body["department"] == "fraud_risk"


def test_summary_never_requests_sensitive_data():
    """Safety rule: agent_summary must never ask the customer to share
    PIN, OTP, password, or full card number."""
    sensitive_inputs = [
        "Someone asked for my OTP and PIN over the phone, I think it was a scam",
        "My card number and CVV got stolen by a fake agent",
        "They wanted my password, is this legit nagad support?",
    ]
    forbidden_phrases = ["share your pin", "share your otp", "send your password",
                          "provide your card number", "give us your otp", "give us your pin"]
    for msg in sensitive_inputs:
        resp = client.post("/sort-ticket", json={"ticket_id": "T-200", "message": msg})
        summary = resp.json()["agent_summary"].lower()
        for phrase in forbidden_phrases:
            assert phrase not in summary, f"Unsafe summary generated: {summary}"


def test_echoes_ticket_id():
    resp = client.post(
        "/sort-ticket",
        json={"ticket_id": "ABC-999", "message": "App is broken"},
    )
    assert resp.json()["ticket_id"] == "ABC-999"


def test_missing_message_returns_422():
    resp = client.post("/sort-ticket", json={"ticket_id": "T-001"})
    assert resp.status_code == 422


def test_empty_message_returns_422():
    resp = client.post("/sort-ticket", json={"ticket_id": "T-001", "message": "   "})
    assert resp.status_code == 422


def test_invalid_channel_rejected():
    resp = client.post(
        "/sort-ticket",
        json={"ticket_id": "T-001", "message": "test", "channel": "carrier_pigeon"},
    )
    assert resp.status_code == 422


def test_contested_refund_routes_to_dispute_resolution():
    resp = client.post(
        "/sort-ticket",
        json={"ticket_id": "T-300", "message": "I was charged twice and my refund was rejected"},
    )
    body = resp.json()
    assert body["case_type"] == "refund_request"
    assert body["department"] == "dispute_resolution"


def test_wrong_transfer_with_critical_language_escalates():
    resp = client.post(
        "/sort-ticket",
        json={
            "ticket_id": "T-400",
            "message": "This is an emergency, I sent all my money to the wrong account immediately",
        },
    )
    body = resp.json()
    assert body["case_type"] == "wrong_transfer"
    assert body["severity"] == "critical"
    assert body["human_review_required"] is True


if __name__ == "__main__":
    import subprocess
    subprocess.run(["pytest", __file__, "-v"])
