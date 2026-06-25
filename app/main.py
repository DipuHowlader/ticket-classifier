"""
FastAPI service implementing:
  GET  /health        -> simple health response
  POST /sort-ticket    -> classify a CRM ticket

Run locally:
    uvicorn app.main:app --host 0.0.0.0 --port 8000

No external API keys or GPU required. Pure rules-based classification
(see app/classifier.py).
"""

from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.classifier import classify_message

app = FastAPI(
    title="CRM Ticket Sorter",
    description="Classifies customer support tickets into case_type, severity, department.",
    version="1.0.0",
)

ALLOWED_CHANNELS = {"app", "sms", "call_center", "merchant_portal"}
ALLOWED_LOCALES = {"bn", "en", "mixed"}


class TicketRequest(BaseModel):
    ticket_id: str = Field(..., description="Unique ticket identifier, echoed back in response")
    channel: Optional[str] = Field(None, description="One of: app, sms, call_center, merchant_portal")
    locale: Optional[str] = Field(None, description="One of: bn, en, mixed")
    message: str = Field(..., description="Free text customer complaint")


class TicketResponse(BaseModel):
    ticket_id: str
    case_type: str
    severity: str
    department: str
    agent_summary: str
    human_review_required: bool
    confidence: float


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/sort-ticket", response_model=TicketResponse)
def sort_ticket(ticket: TicketRequest):
    if not ticket.message or not ticket.message.strip():
        raise HTTPException(status_code=422, detail="message must not be empty")

    if ticket.channel is not None and ticket.channel not in ALLOWED_CHANNELS:
        raise HTTPException(
            status_code=422,
            detail=f"channel must be one of {sorted(ALLOWED_CHANNELS)}",
        )

    if ticket.locale is not None and ticket.locale not in ALLOWED_LOCALES:
        raise HTTPException(
            status_code=422,
            detail=f"locale must be one of {sorted(ALLOWED_LOCALES)}",
        )

    result = classify_message(ticket.message)

    return TicketResponse(
        ticket_id=ticket.ticket_id,
        case_type=result.case_type,
        severity=result.severity,
        department=result.department,
        agent_summary=result.agent_summary,
        human_review_required=result.human_review_required,
        confidence=result.confidence,
    )
