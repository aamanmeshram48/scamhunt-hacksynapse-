"""
ocr_tools.py
============
Screenshot / image analysis pipeline:

    IMAGE -> preprocessing -> OCR text extraction -> structured
    extraction (URLs, phones, emails, UPI IDs) -> QR sub-check
    -> ready to feed into engine.analyze()

Requires Pillow + pytesseract (+ the tesseract binary on PATH).
If unavailable, OCR_AVAILABLE is False and the app must tell the user
clearly rather than fabricating extracted text.
"""

from engine import extract_urls, extract_emails, extract_phones, extract_upi_ids
from qr_tools import decode_qr_image, QR_AVAILABLE

try:
    from PIL import Image, ImageOps, ImageFilter, ImageEnhance
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False


def _preprocess(img):
    """Light preprocessing to improve OCR accuracy on phone screenshots."""
    img = img.convert("L")  # grayscale
    img = ImageOps.autocontrast(img)
    img = img.filter(ImageFilter.SHARPEN)
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(1.4)
    return img


def extract_text_from_image(path):
    """
    Returns (text, error). error is None on success, or a user-facing
    message describing why OCR could not run / produced nothing useful.
    """
    if not OCR_AVAILABLE:
        return "", (
            "OCR is not available in this environment (Pillow/pytesseract/"
            "tesseract binary missing). Install the dependencies listed in "
            "requirements.txt to enable screenshot analysis."
        )

    try:
        img = Image.open(path)
    except Exception as e:
        return "", f"Could not open image file: {e}"

    try:
        processed = _preprocess(img)
        text = pytesseract.image_to_string(processed)
    except Exception as e:
        return "", f"OCR failed to process this image: {e}"

    text = text.strip()
    if not text:
        return "", (
            "We couldn't read any text clearly from this image. "
            "Try uploading a higher-resolution, less blurry screenshot."
        )
    return text, None


def analyze_screenshot(path):
    """
    Full screenshot pipeline. Returns a dict with extracted text,
    structured entities, any decoded QR payloads, and an error/warning
    if something partially failed (pipeline still returns whatever it
    could get rather than aborting entirely).
    """
    result = {
        "ocr_text": "",
        "ocr_error": None,
        "urls": [],
        "emails": [],
        "phones": [],
        "upi_candidates": [],
        "qr_payloads": [],
        "qr_available": QR_AVAILABLE,
    }

    text, err = extract_text_from_image(path)
    result["ocr_text"] = text
    result["ocr_error"] = err

    if text:
        result["urls"] = extract_urls(text)
        result["emails"] = extract_emails(text)
        result["phones"] = extract_phones(text)
        # crude UPI-ID heuristic: word@bank-handle patterns not already flagged as email
        candidates = extract_upi_ids(text)
        known_upi_handles = ("okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "paytm", "upi", "axl", "ibl")
        result["upi_candidates"] = [
            c for c in candidates
            if c not in result["emails"] and any(c.lower().endswith("@" + h) for h in known_upi_handles)
        ]

    if QR_AVAILABLE:
        try:
            result["qr_payloads"] = decode_qr_image(path)
        except Exception:
            result["qr_payloads"] = []

    return result
