"""
email_tools.py
===============
Parses a pasted email (raw .eml text, or plain sender/subject/body
fields typed by the user) and runs phishing-oriented analysis on top
of the shared engine.
"""

import re
from email import message_from_string
from email.utils import parseaddr

from engine import analyze, get_domain, analyze_url_indicators


FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "aol.com", "rediffmail.com",
}

CORPORATE_HINT_WORDS = ["bank", "support", "security", "billing", "accounts", "hr", "payroll", "admin"]


def parse_raw_eml(raw_text):
    """Parse raw .eml-style text into sender/subject/body. Falls back gracefully."""
    try:
        msg = message_from_string(raw_text)
        sender = msg.get("From", "")
        subject = msg.get("Subject", "")
        if msg.is_multipart():
            body_parts = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body_parts.append(part.get_payload(decode=True).decode(errors="ignore"))
                    except Exception:
                        pass
            body = "\n".join(body_parts) if body_parts else raw_text
        else:
            payload = msg.get_payload(decode=True)
            body = payload.decode(errors="ignore") if payload else raw_text
        if sender or subject or body.strip():
            return sender, subject, body
    except Exception:
        pass
    # Not a parseable MIME message -> treat whole thing as body
    return "", "", raw_text


def analyze_email(sender="", subject="", body="", raw_eml=""):
    """
    Analyze an email given either separated fields or a raw pasted email.
    Returns a dict combining sender/domain analysis with the core text
    engine's analysis of subject+body.
    """
    if raw_eml.strip() and not (sender or body):
        sender, subject, body = parse_raw_eml(raw_eml)

    display_name, addr = parseaddr(sender)
    domain = addr.split("@")[-1].lower() if "@" in addr else ""

    combined_text = f"{subject}\n{body}"
    base = analyze(combined_text)

    indicators = list(base["indicators"])
    reasons = list(base["reasons"])
    categories = list(base["categories"])
    score = base["score"]

    # Display-name / address mismatch (e.g. "Bank Support" <random123@gmail.com>)
    if display_name:
        dn_lower = display_name.lower()
        if any(word in dn_lower for word in CORPORATE_HINT_WORDS) and domain in FREEMAIL_DOMAINS:
            score += 20
            indicators.append("DISPLAY NAME MISMATCH")
            categories.append("IDENTITY IMPERSONATION")
            reasons.append(
                f"Sender display name ('{display_name}') suggests an official/corporate sender, "
                f"but the actual address uses a free public email domain ('{domain}')."
            )

    # Domain used in URLs vs sender domain mismatch
    if domain:
        for u in base["urls"]:
            udomain = get_domain(u)
            if udomain and domain not in udomain and udomain not in domain:
                score += 10
                indicators.append("LINK/SENDER DOMAIN MISMATCH")
                categories.append("PHISHING")
                reasons.append(
                    f"Email links to '{udomain}', which does not match the sender's domain '{domain}'."
                )
                break

    score = max(0, min(100, score))
    indicators = list(dict.fromkeys(indicators))
    reasons = list(dict.fromkeys(reasons))
    categories = list(dict.fromkeys(categories)) or ["NO CLEAR THREAT CATEGORY"]

    from engine import risk_level_from_score, recommended_action
    level, color = risk_level_from_score(score)

    return {
        "sender_display_name": display_name,
        "sender_address": addr,
        "sender_domain": domain,
        "subject": subject,
        "score": score,
        "level": level,
        "color": color,
        "categories": categories,
        "indicators": indicators,
        "reasons": reasons,
        "action": recommended_action(level),
        "urls": base["urls"],
        "emails": base["emails"],
        "phones": base["phones"],
    }
