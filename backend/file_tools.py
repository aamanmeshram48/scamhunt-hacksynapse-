"""
file_tools.py
=============
Safe, static (never-execute) analysis of an uploaded file.

Only reads bytes from disk. Never runs, imports, or executes the
uploaded file's content. Designed to degrade gracefully: if a deeper
check isn't possible (e.g. no antivirus engine available), the module
says so explicitly instead of inventing a verdict.
"""

import hashlib
import mimetypes
import os
import re
import zipfile

MAX_SAFE_SIZE = 50 * 1024 * 1024  # 50 MB guardrail for in-app static analysis

EXECUTABLE_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".jar", ".apk", ".dll", ".sh",
}

MACRO_ENABLED_OFFICE = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

DOCUMENT_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".csv", ".txt"}

# Magic-byte signatures -> real file type, used to catch extension mismatch
MAGIC_SIGNATURES = [
    (b"MZ", "PE Executable (.exe/.dll)"),
    (b"%PDF", "PDF Document"),
    (b"PK\x03\x04", "ZIP/Office Open XML container"),
    (b"\xd0\xcf\x11\xe0", "Legacy MS Office (OLE2) document"),
    (b"\x7fELF", "Linux ELF Executable"),
    (b"\xca\xfe\xba\xbe", "Java class/Mach-O universal binary"),
    (b"\x89PNG", "PNG Image"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"GIF8", "GIF Image"),
    (b"Rar!", "RAR Archive"),
    (b"7z\xbc\xaf", "7-Zip Archive"),
]


def sha256_file(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def _detect_magic(head):
    for sig, label in MAGIC_SIGNATURES:
        if head.startswith(sig):
            return label
    return None


def _extract_urls_from_bytes(data):
    try:
        text = data.decode("latin-1", errors="ignore")
    except Exception:
        text = ""
    return list(set(re.findall(r"https?://[^\s\"'<>\\]{4,200}", text)))


def analyze_file(path, original_filename=None):
    """
    Perform safe static analysis on a file already saved to disk.
    Returns a result dict. Never executes the file.
    """
    result = {
        "filename": original_filename or os.path.basename(path),
        "size": None,
        "mime_guess": None,
        "declared_ext": None,
        "detected_type": None,
        "extension_mismatch": False,
        "sha256": None,
        "indicators": [],
        "reasons": [],
        "urls_found": [],
        "confidence_note": (
            "This is a static, offline heuristic check (no live antivirus "
            "engine or malware-signature database is connected). Treat the "
            "result as an initial screening, not a definitive verdict."
        ),
        "score": 0,
        "level": "LOW RISK",
        "action": "",
        "error": None,
    }

    try:
        size = os.path.getsize(path)
    except OSError as e:
        result["error"] = f"Could not read file: {e}"
        return result

    result["size"] = size
    fname = result["filename"]
    _, ext = os.path.splitext(fname.lower())
    result["declared_ext"] = ext or "(none)"
    result["mime_guess"] = mimetypes.guess_type(fname)[0] or "unknown"

    if size == 0:
        result["error"] = "File is empty (0 bytes)."
        return result

    if size > MAX_SAFE_SIZE:
        result["indicators"].append("OVERSIZED FILE")
        result["reasons"].append(
            f"File is larger than the {MAX_SAFE_SIZE // (1024*1024)} MB limit for in-app static analysis; only a partial header check was performed."
        )
        result["score"] += 10

    try:
        result["sha256"] = sha256_file(path)
    except Exception as e:
        result["error"] = f"Hashing failed: {e}"

    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except Exception as e:
        result["error"] = f"Could not read file header: {e}"
        return result

    detected = _detect_magic(head)
    result["detected_type"] = detected or "Unknown / not a recognized signature"

    # ---- Extension mismatch check ----
    if detected:
        mismatch = False
        if ext in {".exe", ".dll", ".scr", ".com"} and detected != "PE Executable (.exe/.dll)":
            mismatch = True
        if ext == ".pdf" and detected != "PDF Document":
            mismatch = True
        if ext in {".jpg", ".jpeg"} and detected != "JPEG Image":
            mismatch = True
        if ext == ".png" and detected != "PNG Image":
            mismatch = True
        if ext in DOCUMENT_EXTENSIONS - {".pdf", ".txt", ".csv"} and detected not in (
            "ZIP/Office Open XML container", "Legacy MS Office (OLE2) document"
        ):
            mismatch = True
        if detected == "PE Executable (.exe/.dll)" and ext not in {".exe", ".dll", ".scr", ".com", ".sys"}:
            mismatch = True

        if mismatch:
            result["extension_mismatch"] = True
            result["indicators"].append("EXTENSION MISMATCH")
            result["reasons"].append(
                f"File extension '{ext}' does not match the file's actual content type ('{detected}'). "
                "This is a common technique used to disguise malicious files."
            )
            result["score"] += 35

    # ---- Executable extension ----
    if ext in EXECUTABLE_EXTENSIONS:
        result["indicators"].append("EXECUTABLE FILE TYPE")
        result["reasons"].append(
            f"'{ext}' is an executable/script file type. Executable files should never be run unless you fully trust the sender and source."
        )
        result["score"] += 30

    # ---- Macro-enabled office docs ----
    if ext in MACRO_ENABLED_OFFICE:
        result["indicators"].append("MACRO-ENABLED DOCUMENT")
        result["reasons"].append(
            "This file type supports embedded macros, which are a common malware delivery method. Do not enable macros/content unless you are certain of the source."
        )
        result["score"] += 25

    # ---- Double extension trick, e.g. invoice.pdf.exe ----
    parts = fname.lower().split(".")
    if len(parts) > 2 and parts[-1] in {x.strip(".") for x in EXECUTABLE_EXTENSIONS}:
        result["indicators"].append("DOUBLE EXTENSION")
        result["reasons"].append(
            "Filename contains multiple extensions (e.g. 'document.pdf.exe'), a classic trick to disguise an executable as a harmless document."
        )
        result["score"] += 30

    # ---- Search for embedded URLs in raw bytes (works for scripts/macros/plaintext) ----
    try:
        with open(path, "rb") as f:
            raw = f.read(min(size, 5 * 1024 * 1024))
        urls = _extract_urls_from_bytes(raw)
        if urls:
            result["urls_found"] = urls[:25]
            result["indicators"].append("EMBEDDED URL(S)")
            result["reasons"].append(f"{len(urls)} URL(s) found embedded in the file content.")
            result["score"] += 8
    except Exception:
        pass

    # ---- ZIP/Office-based containers: look for macro/VBA project markers ----
    if detected == "ZIP/Office Open XML container":
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if any("vbaProject.bin" in n for n in names):
                    result["indicators"].append("VBA MACRO PROJECT")
                    result["reasons"].append("Document contains an embedded VBA macro project.")
                    result["score"] += 25
        except Exception:
            pass

    result["indicators"] = list(dict.fromkeys(result["indicators"]))
    result["reasons"] = list(dict.fromkeys(result["reasons"]))
    result["score"] = max(0, min(100, result["score"]))

    from engine import risk_level_from_score, recommended_action
    level, _color = risk_level_from_score(result["score"])
    result["level"] = level
    result["action"] = recommended_action(level)

    if not result["indicators"]:
        result["reasons"].append("No suspicious static indicators were found in this basic check.")

    return result
