"""
qr_tools.py
===========
QR code decoding + payment-QR specific parsing.

Decoding requires 'pyzbar' (and its native zbar library) plus Pillow.
If pyzbar is not installed, QR_AVAILABLE is False and the app will show
a clear message instead of pretending to decode anything.
"""

import re
from urllib.parse import urlparse, parse_qs

try:
    from pyzbar.pyzbar import decode as _zbar_decode
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False


def decode_qr_image(path):
    """Return a list of decoded string payloads found in the image, or [] if none/unavailable."""
    if not QR_AVAILABLE:
        return []
    try:
        img = Image.open(path)
        results = _zbar_decode(img)
        return [r.data.decode("utf-8", errors="ignore") for r in results]
    except Exception:
        return []


def is_upi_uri(payload):
    return payload.lower().startswith("upi://pay")


def parse_upi_uri(payload):
    """Parse a UPI payment URI (upi://pay?pa=...&pn=...&am=...) into fields."""
    parsed = urlparse(payload)
    q = parse_qs(parsed.query)
    fields = {
        "payee_vpa": q.get("pa", [""])[0],
        "payee_name": q.get("pn", [""])[0],
        "amount": q.get("am", [""])[0],
        "currency": q.get("cu", [""])[0],
        "note": q.get("tn", [""])[0],
        "merchant_code": q.get("mc", [""])[0],
    }
    return fields


def analyze_qr_payload(payload):
    """
    Classify a decoded QR payload and return risk-relevant structured info.
    """
    info = {
        "raw": payload,
        "type": "unknown",
        "urls": [],
        "upi": None,
        "indicators": [],
        "reasons": [],
        "score": 0,
    }

    if payload.lower().startswith(("http://", "https://")):
        info["type"] = "url"
        info["urls"] = [payload]
    elif is_upi_uri(payload):
        info["type"] = "payment (UPI)"
        info["upi"] = parse_upi_uri(payload)
        if not info["upi"]["payee_vpa"]:
            info["indicators"].append("MISSING PAYEE ID")
            info["reasons"].append("Payment QR does not clearly specify a payee VPA/ID.")
            info["score"] += 15
        if info["upi"]["amount"]:
            info["indicators"].append("PRE-FILLED AMOUNT")
            info["reasons"].append(
                f"This QR pre-fills a payment amount ({info['upi']['amount']} {info['upi']['currency'] or ''}). "
                "Confirm this matches what you actually intend to pay before approving."
            )
            info["score"] += 8
    elif re.match(r"^\+?\d{7,15}$", payload.strip()):
        info["type"] = "phone number"
    elif "@" in payload and " " not in payload and "." in payload.split("@")[-1]:
        info["type"] = "email / contact"
    else:
        info["type"] = "text"

    # generic URL scan inside any payload type (some QR text embeds a link)
    found = re.findall(r"https?://[^\s]+", payload)
    if found and not info["urls"]:
        info["urls"] = found

    if info["urls"]:
        from engine import analyze_url_indicators
        for u in info["urls"]:
            s, ind, cat, rs = analyze_url_indicators(u)
            info["score"] += s
            info["indicators"].extend(ind)
            info["reasons"].extend(rs)

    info["indicators"] = list(dict.fromkeys(info["indicators"]))
    info["reasons"] = list(dict.fromkeys(info["reasons"]))
    info["score"] = max(0, min(100, info["score"]))

    from engine import risk_level_from_score, recommended_action
    level, _c = risk_level_from_score(info["score"])
    info["level"] = level
    info["action"] = recommended_action(level)

    return info
