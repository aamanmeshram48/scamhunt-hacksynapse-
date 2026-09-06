"""
case_manager.py
================
Incident Response case/evidence data model and JSON-backed persistence.

A "Case" bundles together every piece of evidence (URL, text, screenshot,
file, QR, email) a user adds while investigating a single incident, plus
the AI (heuristic) analysis for the case as a whole.

No external database engine is required: cases are persisted as a single
JSON document per case under ./data/cases/<case_id>.json. This keeps the
app dependency-free while still being a real, inspectable data store that
could later be swapped for SQLite/Postgres without changing the API of
this module.
"""

import json
import os
import random
import string
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CASES_DIR = os.path.join(DATA_DIR, "cases")

STATUSES = ["New", "Under Analysis", "Action Required", "Reported", "Resolved", "Archived"]


def _ensure_dirs():
    os.makedirs(CASES_DIR, exist_ok=True)


def generate_case_id():
    _ensure_dirs()
    year = datetime.now().year
    while True:
        suffix = "".join(random.choices(string.digits, k=6))
        case_id = f"SCAM-{year}-{suffix}"
        if not os.path.exists(os.path.join(CASES_DIR, f"{case_id}.json")):
            return case_id


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


class Case:
    def __init__(self, case_id=None, description=""):
        _ensure_dirs()
        self.case_id = case_id or generate_case_id()
        self.created_at = now_iso()
        self.updated_at = self.created_at
        self.status = "New"
        self.description = description
        self.category = "NO CLEAR THREAT CATEGORY"
        self.risk_level = "LOW RISK"
        self.risk_score = 0
        self.evidence = []      # list of evidence dicts
        self.analysis_log = []  # list of per-evidence analysis dicts
        self.timeline = []      # list of {ts, event}
        self.add_timeline_event("Case created.")

    # ---------------- timeline / evidence ----------------

    def add_timeline_event(self, text):
        self.timeline.append({"ts": now_iso(), "event": text})
        self.updated_at = now_iso()

    def add_evidence(self, ev_type, data, analysis=None, original_filename=None, sha256=None):
        """
        ev_type: one of 'url','text','image','file','qr','payment_qr','email'
        data: raw content or reference (e.g. text string, or stored file path)
        analysis: the analysis-engine result dict for this evidence, if any
        """
        evidence_id = f"EV-{len(self.evidence) + 1:03d}"
        record = {
            "evidence_id": evidence_id,
            "type": ev_type,
            "data": data,
            "original_filename": original_filename,
            "sha256": sha256,
            "created_at": now_iso(),
        }
        self.evidence.append(record)
        if analysis:
            self.analysis_log.append({
                "evidence_id": evidence_id,
                "type": ev_type,
                "analysis": analysis,
                "created_at": now_iso(),
            })
        self._recompute_case_level()
        self.add_timeline_event(f"Added {ev_type} evidence ({evidence_id}).")
        return evidence_id

    def _recompute_case_level(self):
        """Case risk = highest risk among all evidence analyzed so far."""
        best_score = 0
        best_categories = []
        for entry in self.analysis_log:
            a = entry["analysis"]
            score = a.get("score", 0)
            if score > best_score:
                best_score = score
                best_categories = a.get("categories", [])
        if self.analysis_log:
            from engine import risk_level_from_score
            level, _ = risk_level_from_score(best_score)
            self.risk_score = best_score
            self.risk_level = level
            if best_categories:
                self.category = best_categories[0]
            if self.status == "New":
                self.status = "Under Analysis"

    def set_status(self, status):
        if status in STATUSES:
            self.status = status
            self.add_timeline_event(f"Status changed to '{status}'.")

    # ---------------- case-aware AI assistant ----------------

    def all_indicators(self):
        ind = []
        for entry in self.analysis_log:
            ind.extend(entry["analysis"].get("indicators", []))
        return list(dict.fromkeys(ind))

    def all_categories(self):
        cats = []
        for entry in self.analysis_log:
            cats.extend(entry["analysis"].get("categories", []))
        return list(dict.fromkeys(cats))

    def all_recommendations(self):
        recs = []
        for entry in self.analysis_log:
            a = entry["analysis"]
            if a.get("action"):
                recs.append(a["action"])
        return list(dict.fromkeys(recs))

    def summary(self):
        n_evidence = len(self.evidence)
        cats = ", ".join(self.all_categories()) or "no clear category"
        return (
            f"Case {self.case_id} contains {n_evidence} piece(s) of evidence. "
            f"Overall risk assessed as {self.risk_level} (score {self.risk_score}/100). "
            f"Likely category/categories: {cats}. Current status: {self.status}."
        )

    def ask_assistant(self, question):
        """
        Very small rule-based Q&A over the case's aggregated evidence.
        This is NOT a general chatbot -- it only reasons over data already
        collected in this case, and says so when a question falls outside
        that scope.
        """
        q = question.lower().strip()

        if not self.evidence:
            return "No evidence has been added to this case yet. Add a URL, message, screenshot, file, QR code, or email first."

        if any(k in q for k in ["summar", "overview", "what happened"]):
            return self.summary()

        if any(k in q for k in ["what kind", "what type", "category", "categor"]):
            cats = self.all_categories()
            return "Based on the evidence collected, this case most closely matches: " + ", ".join(cats) + "." if cats else \
                   "No strong scam/threat category was identified from the evidence collected so far."

        if any(k in q for k in ["evidence is suspicious", "what evidence", "which evidence", "indicators"]):
            ind = self.all_indicators()
            if not ind:
                return "No specific suspicious indicators have been detected in the evidence collected so far."
            return "Indicators detected across this case's evidence: " + ", ".join(ind) + "."

        if any(k in q for k in ["what should i do", "next step", "what next", "advice"]):
            recs = self.all_recommendations()
            if not recs:
                return "No strong risk indicators were found, but always verify unexpected requests independently."
            return " | ".join(recs)

        if any(k in q for k in ["preserve", "what information should i keep", "what to keep"]):
            return (
                "Preserve: full screenshots (including timestamps/usernames), original URLs, "
                "sender email addresses/phone numbers, any transaction/reference IDs, and this case's "
                "exported evidence report. Do not edit or delete original evidence."
            )

        if any(k in q for k in ["avoid", "not do", "should i not", "don't", "dont"]):
            return (
                "Do not: send additional money, share OTP/PIN/passwords, click unresolved suspicious links again, "
                "confront or retaliate against the sender, or delete messages/accounts that contain evidence."
            )

        if any(k in q for k in ["report", "who do i contact", "reporting", "police", "cybercrime"]):
            return (
                "In India: file a complaint at the National Cyber Crime Reporting Portal (https://cybercrime.gov.in) "
                "or call the Cyber Crime Helpline 1930. For financial fraud, also contact your bank's fraud helpline "
                "immediately to attempt a transaction freeze. Outside India, contact your local police non-emergency "
                "line and your bank/payment provider."
            )

        if any(k in q for k in ["risk", "how bad", "how dangerous", "severity"]):
            return f"This case's overall risk level is {self.risk_level} (score {self.risk_score}/100)."

        return (
            "I can answer questions about this case's category, detected indicators, recommended next steps, "
            "what evidence to preserve, what to avoid doing, reporting options, and overall risk/summary. "
            "Try asking one of those directly."
        )

    # ---------------- serialization ----------------

    def to_dict(self):
        return {
            "case_id": self.case_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "category": self.category,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "description": self.description,
            "evidence": self.evidence,
            "analysis_log": self.analysis_log,
            "timeline": self.timeline,
        }

    @classmethod
    def from_dict(cls, d):
        c = cls.__new__(cls)
        c.case_id = d["case_id"]
        c.created_at = d["created_at"]
        c.updated_at = d["updated_at"]
        c.status = d["status"]
        c.category = d["category"]
        c.risk_level = d["risk_level"]
        c.risk_score = d["risk_score"]
        c.description = d["description"]
        c.evidence = d["evidence"]
        c.analysis_log = d["analysis_log"]
        c.timeline = d["timeline"]
        return c

    def save(self):
        _ensure_dirs()
        path = os.path.join(CASES_DIR, f"{self.case_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        return path

    @classmethod
    def load(cls, case_id):
        path = os.path.join(CASES_DIR, f"{case_id}.json")
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    @classmethod
    def list_all(cls):
        _ensure_dirs()
        cases = []
        for fname in sorted(os.listdir(CASES_DIR), reverse=True):
            if fname.endswith(".json"):
                try:
                    cases.append(cls.load(fname[:-5]))
                except Exception:
                    continue
        return cases

    @classmethod
    def delete(cls, case_id):
        path = os.path.join(CASES_DIR, f"{case_id}.json")
        if os.path.exists(path):
            os.remove(path)
