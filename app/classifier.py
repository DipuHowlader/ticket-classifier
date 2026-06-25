"""
Rules-based ticket classifier.

Strategy:
- Score each case_type using weighted keyword/phrase/regex matches.
- Support English, Bangla script, and common Banglish (romanized Bangla) terms,
  since the support desk receives messages in bn / en / mixed locales.
- Phishing/social-engineering detection takes priority and forces critical + review.
- Severity is derived from case_type plus intensifier words (e.g. "urgent", "all my money").
- agent_summary is template-generated from detected entities (amount, channel hints)
  and is hard-filtered to never leak/request PIN, OTP, password, or full card number.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Keyword / pattern banks
# ---------------------------------------------------------------------------

# Each entry: (compiled_regex, weight)
def _kw(words):
    """Build a case-insensitive regex matching any of the given words/phrases."""
    escaped = [re.escape(w) for w in words]
    pattern = r"(" + "|".join(escaped) + r")"
    return re.compile(pattern, re.IGNORECASE)


PHISHING_PATTERNS = _kw([
    "otp", "one time password", "pin", "password", "cvv", "card number",
    "social engineering", "phishing", "scam", "scammer", "fraud call",
    "ask for my pin", "asked my pin", "asked for my otp", "asked my otp",
    "share my pin", "share my otp", "verification code", "security code",
    "impersonat", "fake call", "fake agent", "fake bkash", "fake nagad",
    "pretending to be", "claims to be from", "calling from bkash",
    "calling from nagad", "calling from bank", "is that bkash", "is this bkash",
    "is that nagad", "asked me to share", "bishesh code", "gopon code",
    "amar pin", "amar otp", "pin code chaise", "otp chaise", "pin number diye",
])

WRONG_TRANSFER_PATTERNS = _kw([
    "wrong number", "wrong recipient", "sent to wrong", "sent money to wrong",
    "wrong account", "incorrect number", "by mistake", "mistakenly sent",
    "ulta number", "vul number", "vhul number", "send kore disi vul",
    "taka pathaisi vul", "wrong person", "transferred to the wrong",
    "wrong bkash number", "wrong nagad number",
])

PAYMENT_FAILED_PATTERNS = _kw([
    "payment failed", "transaction failed", "failed but balance deducted",
    "balance deducted", "taka kete নিয়েছে", "taka kete felese",
    "deducted but", "money deducted", "transaction unsuccessful",
    "payment error", "payment didn't go through", "payment did not go through",
    "txn failed", "balance cut", "amount debited", "debited but not",
    "send failed", "recharge failed",
])

REFUND_PATTERNS = _kw([
    "refund", "money back", "want my money back", "changed my mind",
    "cancel my order", "cancel the order", "return the payment",
    "ferot", "taka ferot", "ফেরত",
])

OTHER_HINT_PATTERNS = _kw([
    "app crashed", "app crash", "not opening", "won't open", "wont open",
    "login issue", "can't log in", "cannot log in", "bug", "error message",
    "app is slow", "freezing", "freeze", "force close", "update issue",
])

# Intensifier / severity-bumping language
CRITICAL_WORDS = _kw([
    "all my money", "everything i have", "life savings", "entire balance",
    "lost everything", "emergency", "urgent", "immediately", "right now",
    "scammer", "scam", "fraud", "being threatened", "threatened me",
])

HIGH_INTENSITY_WORDS = _kw([
    "large amount", "big amount", "a lot of money", "significant amount",
    "important", "asap", "as soon as possible",
])

# Amount extraction: numbers followed by/near currency words, or just standalone
# large numbers near money-related verbs.
AMOUNT_PATTERN = re.compile(
    r"(?P<amount>[\d,]+(?:\.\d+)?)\s*(?P<currency>taka|tk|bdt|৳)?",
    re.IGNORECASE,
)

CURRENCY_WORD = re.compile(r"\b(taka|tk|bdt|৳)\b", re.IGNORECASE)


@dataclass
class ClassificationResult:
    case_type: str
    severity: str
    department: str
    agent_summary: str
    human_review_required: bool
    confidence: float


CASE_TYPE_TO_DEFAULT_DEPARTMENT = {
    "wrong_transfer": "dispute_resolution",
    "payment_failed": "payments_ops",
    "refund_request": "customer_support",  # may bump to dispute_resolution if contested
    "phishing_or_social_engineering": "fraud_risk",
    "other": "customer_support",
}

CONTESTED_REFUND_PATTERNS = _kw([
    "denied my refund", "refused to refund", "refund was rejected",
    "dispute", "not refunded", "still no refund", "refund declined",
    "wrongly charged", "unauthorized charge", "charged twice", "double charged",
])


def _extract_amount(message: str) -> Optional[str]:
    """Best-effort extraction of a monetary amount mention, for the summary."""
    has_currency_word = bool(CURRENCY_WORD.search(message))
    for match in AMOUNT_PATTERN.finditer(message):
        amt = match.group("amount")
        cur = match.group("currency")
        # Skip bare ticket-like numbers with no currency context unless currency
        # word appears elsewhere nearby in the message.
        if cur:
            return f"{amt} BDT"
        if has_currency_word and len(amt.replace(",", "")) >= 2:
            return f"{amt} BDT"
    return None


def _score(patterns: re.Pattern, message: str) -> int:
    return len(patterns.findall(message))


def classify_message(message: str) -> ClassificationResult:
    text = message.strip()

    scores = {
        "phishing_or_social_engineering": _score(PHISHING_PATTERNS, text) * 3,  # high weight, priority case
        "wrong_transfer": _score(WRONG_TRANSFER_PATTERNS, text) * 2,
        "payment_failed": _score(PAYMENT_FAILED_PATTERNS, text) * 2,
        "refund_request": _score(REFUND_PATTERNS, text) * 2,
        "other": _score(OTHER_HINT_PATTERNS, text),
    }

    # If nothing matched at all, default to "other" with low confidence.
    total_signal = sum(scores.values())
    if total_signal == 0:
        case_type = "other"
        raw_confidence = 0.4
    else:
        case_type = max(scores, key=scores.get)
        # crude confidence: how dominant is the winning score vs total signal
        raw_confidence = round(min(0.95, 0.55 + 0.1 * scores[case_type]), 2)

    # --- Severity ---
    is_critical_language = bool(CRITICAL_WORDS.search(text))
    is_high_intensity = bool(HIGH_INTENSITY_WORDS.search(text))

    if case_type == "phishing_or_social_engineering":
        severity = "critical"
    elif case_type == "wrong_transfer":
        severity = "critical" if is_critical_language else "high"
    elif case_type == "payment_failed":
        severity = "critical" if is_critical_language else "high"
    elif case_type == "refund_request":
        if is_critical_language:
            severity = "high"
        elif is_high_intensity or CONTESTED_REFUND_PATTERNS.search(text):
            severity = "medium"
        else:
            severity = "low"
    else:  # other
        severity = "medium" if (is_critical_language or is_high_intensity) else "low"

    # --- Department ---
    department = CASE_TYPE_TO_DEFAULT_DEPARTMENT[case_type]
    if case_type == "refund_request" and CONTESTED_REFUND_PATTERNS.search(text):
        department = "dispute_resolution"

    # --- human_review_required ---
    human_review_required = (severity == "critical") or (
        case_type == "phishing_or_social_engineering"
    )

    # --- agent_summary (safety: never request/echo PIN, OTP, password, full card number) ---
    agent_summary = _build_summary(case_type, text)

    confidence = raw_confidence

    return ClassificationResult(
        case_type=case_type,
        severity=severity,
        department=department,
        agent_summary=agent_summary,
        human_review_required=human_review_required,
        confidence=confidence,
    )


_SENSITIVE_TERMS = _kw(["pin", "otp", "password", "cvv", "card number"])


def _sanitize_summary(summary: str) -> str:
    """
    Defense-in-depth: ensure the generated summary never contains language that
    could be read as soliciting PIN/OTP/password/full card number. We only ever
    template these summaries ourselves, but we double-check before returning.
    """
    if _SENSITIVE_TERMS.search(summary):
        # Replace any sensitive-term mention with a neutral reference, since the
        # summary should describe the *situation*, never request the data itself.
        summary = _SENSITIVE_TERMS.sub("sensitive account details", summary)
    return summary


def _build_summary(case_type: str, text: str) -> str:
    amount = _extract_amount(text)

    if case_type == "wrong_transfer":
        if amount:
            summary = f"Customer reports sending {amount} to the wrong recipient and requests recovery."
        else:
            summary = "Customer reports sending money to the wrong recipient and requests recovery."
    elif case_type == "payment_failed":
        if amount:
            summary = f"Customer reports a failed transaction of {amount} where the balance was deducted."
        else:
            summary = "Customer reports a failed transaction where the balance may have been deducted."
    elif case_type == "refund_request":
        if amount:
            summary = f"Customer is requesting a refund of {amount} for a recent transaction."
        else:
            summary = "Customer is requesting a refund for a recent transaction."
    elif case_type == "phishing_or_social_engineering":
        summary = (
            "Customer reports being contacted by a suspicious caller or message "
            "impersonating a financial service and requesting sensitive account details."
        )
    else:
        summary = "Customer reports a general app or account issue requiring review."

    return _sanitize_summary(summary)
