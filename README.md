# 🛡️ ScamHunt  —  Mobile Threat Defense Suite

> **Winner-grade cybersecurity suite** empowering citizens and organizations to **detect, assess, contain, and legally preserve evidence** against digital scams, phishing messages, extortion, authority impersonation, and fraudulent UPI payment requests.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Android](https://img.shields.io/badge/Platform-Android%2014-green.svg)](android/)
[![Frontend: PWA](https://img.shields.io/badge/Frontend-Responsive%20PWA-orange.svg)](frontend/)
[![Backend: Python](https://img.shields.io/badge/Backend-Python%203.10%2B-yellow.svg)](backend/)
[![Legal: Section 65B](https://img.shields.io/badge/Evidence-Section%2065B%20Compliant-red.svg)](docs/SECTION_65B_LEGAL.md)

---

## 📌 Executive Summary

Digital fraud in India causes billions of rupees in losses annually via electricity bill cut-off threats, fake SBI/HDFC KYC deactivations, fraudulent UPI QR codes, remote access APK coercion, and digital arrest extortion. 

**ScamHunt 2.0** provides a complete, 100% offline-capable threat defense suite:
1. **Explainable AI Scam Scanner:** Instant multi-vector threat scoring (0–100) that tells users *exactly why* a message is dangerous with zero hallucinations.
2. **Emergency 1930 Incident Response:** One-tap connection to India's National Cyber Crime Helpline (`tel:1930`) paired with an interactive 5-step containment checklist.
3. **Section 65B Cryptographic Evidence Stamping:** In-browser and on-device SHA-256 tamper-proof evidence generator compliant with the Indian Evidence Act and Bharatiya Sakshya Adhiniyam, 2023.
4. **Native Android Experience:** Native Kotlin application utilizing the Android `MediaStore` Downloads bridge and edge-to-edge layout.

---

## 📱 The 8 Core Stitched Screen Flows

| Screen | Identifier | Core Capabilities |
|---|---|---|
| **1. Splash & Welcome** | `5902862a` | High-impact radar animation, multi-vector scanner overview, onboarding. |
| **2. Authentication** | `26dbe891` | PIN / Biometric simulation + **Emergency Attack Bypass** (skip login during active fraud). |
| **3. Home Dashboard** | `880d1969` | Real-time threat status monitor, quick scan launchers, recent case timeline. |
| **4. Multi-Vector Scan Hub** | `1be329c7` | Analyzes SMS, URLs, UPI IDs, and Files. 5 Quick-Preset test chips. |
| **5. Threat Analysis Detail** | `b1f07ea8` | Circular animated SVG risk gauge (0–100), detected category chips, explainable reasons. |
| **6. Incident Response** | `9ca374f6` | 1930 Helpline dialer, 5-step containment checklist, real-time case log. |
| **7. Evidence Creator** | `62a7e750` | SHA-256 integrity seal, Section 65B dossier export (TXT, JSON, PDF, Helpline Script). |
| **8. Profile & Settings** | `6fc70747` | Emergency SOS directory, offline-first toggle, sensitivity adjustment, developer modal. |

---

## 🏗️ Repository Structure

```
scamhunt2.0/
├── frontend/                       # Web & PWA Application (Responsive, 8 screens, 100% offline-first)
│   ├── index.html                  # Latest UI redesign (87KB, Team CyberNova modal, 8 screen views)
│   ├── manifest.json               # Progressive Web App manifest
│   ├── sw.js                       # Service Worker for offline asset caching
│   ├── serve.py / serve.ps1        # Dedicated frontend web server runners
│   ├── css/styles.css              # Custom Tailwind & Material 3 theme styling
│   ├── js/app.js                   # Screen navigation, modals, and event orchestration
│   ├── js/engine.js                # Browser-side heuristic threat scoring engine & SHA-256 WebCrypto
│   ├── js/caseManager.js           # LocalStorage case manager & Section 65B dossier exporter
│   └── assets/                     # App logo and team photo
│
├── backend/                        # Python Cybersecurity Analysis Suite & REST API
│   ├── app.py                      # Desktop GUI application (Tkinter, Incident Center)
│   ├── api.py                      # Lightweight zero-dependency HTTP REST API (/api/analyze, /api/cases, /api/export)
│   ├── engine.py                   # Core heuristic threat detection engine
│   ├── case_manager.py             # Incident tracking & state management
│   ├── evidence_export.py          # Section 65B legal evidence stamping & report generator
│   ├── file_tools.py               # APK inspection, binary hashes & entropy checker
│   ├── ocr_tools.py                # Screenshot OCR image text extraction (Tesseract)
│   ├── qr_tools.py                 # Malicious QR code decoding & threat inspection (pyzbar)
│   ├── email_tools.py              # Phishing email (.eml) & header analyzer
│   ├── requirements.txt            # Python dependencies (Pillow, pytesseract, pyzbar, reportlab)
│   └── .env.example                # Configuration template (offline defaults)
│
├── ml-model/                       # Threat Intelligence & Heuristic AI/ML Specifications
│   ├── rules_database.json         # Structured heuristic rule definitions, weights, and categories
│   ├── test_samples.json           # Evaluation dataset of phishing, fraud, and legitimate samples
│   ├── evaluate_model.py           # Automated evaluation benchmark (100% accuracy, 0.12ms latency)
│   └── README.md                   # Explainable AI design and architecture documentation
│
├── android/                        # Native Android Application (Kotlin WebView Wrapper)
│   ├── build.gradle                # Root Gradle configuration
│   ├── settings.gradle             # Project settings
│   ├── gradlew / gradlew.bat       # Gradle wrappers
│   ├── app/build.gradle            # App module (compileSdk 34, targetSdk 34, Kotlin 1.9.22)
│   └── app/src/main/
│       ├── AndroidManifest.xml     # Permissions & launcher configuration
│       ├── java/com/scamhunt/app/MainActivity.kt  # Native WebView, Section 65B MediaStore file saver
│       ├── res/                    # Native Android drawables, layouts, styles
│       └── assets/                 # Bundled offline web assets for APK (synced with frontend)
│
├── docs/                           # Comprehensive Documentation & Hackathon Artifacts
│   ├── ARCHITECTURE.md             # System architecture, data flow & security model
│   ├── SECTION_65B_LEGAL.md        # Section 65B Indian Evidence Act compliance guide
│   ├── TEAM_DISTRIBUTION.md        # Team roles and responsibilities
│   ├── PROGRESS_REPORT.md          # Hackathon checkpoint progress report
│   ├── FUTURE_SCOPE.md             # Roadmap and feature expansion
│   ├── scamhuntPPT1.pptx           # Official presentation slide deck
│   └── stitch_design/              # Original Google Stitch UI mockups & metadata
│
├── release/                        # Release Distribution Artifacts
│   ├── ScamHunt-final.apk          # Pre-built standalone release APK (3.78MB, SHA-256 verified)
│   └── README.md                   # APK installation guide & verification hash
│
├── .gitignore                      # Clean repository ignore rules
├── serve.py / serve.ps1            # Root convenience dev server runners
└── README.md                       # Master project documentation
```

---

## 🚀 Quick Start Guide

### Option 1: Run the Web App / PWA (Zero Dependencies)

Open directly in any modern web browser:
```bash
# Using Python (standard library - no external packages needed)
python serve.py
```
Or with PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\serve.ps1
```
> The application will automatically open at `http://localhost:8080`.

---

### Option 2: Run the Backend & REST API

ScamHunt includes a zero-external-dependency REST API for integrations:

```bash
cd backend
python api.py --port 8000
```

**API Endpoints:**
- `GET  /api/health` — Service status and engine capabilities
- `POST /api/analyze` — Analyze message text, URLs, UPI handles, or phone numbers
  ```json
  POST /api/analyze
  {
    "text": "Your electricity connection will be disconnected tonight. Pay immediately: http://wb-pay.top"
  }
  ```
- `GET  /api/cases` — List active incident cases
- `POST /api/export` — Generate Section 65B legal text report

---

### Option 3: Run the Desktop Cybersecurity Suite (Tkinter)

```bash
cd backend
pip install -r requirements.txt
python app.py
```

---

### Option 4: Run the AI/ML Heuristic Evaluation Benchmark

Verify the deterministic AI model against the test dataset:

```bash
python ml-model/evaluate_model.py
```

**Benchmark Output:**
```
======================================================================
  SCAMHUNT 2.0 — AI HEURISTIC MODEL EVALUATION REPORT
======================================================================
Total Test Samples: 10
----------------------------------------------------------------------
[PASS] SAMPLE_01  | Type: phishing_electricity   | Score:  66/100 (HIGH RISK ) | 0.58ms
[PASS] SAMPLE_02  | Type: phishing_sbi_kyc       | Score: 100/100 (CRITICAL  ) | 0.09ms
[PASS] SAMPLE_03  | Type: telegram_task_scam     | Score:  43/100 (SUSPICIOUS) | 0.09ms
[PASS] SAMPLE_04  | Type: lottery_kbc            | Score:  83/100 (CRITICAL  ) | 0.06ms
[PASS] SAMPLE_05  | Type: remote_access_scam     | Score:  68/100 (HIGH RISK ) | 0.07ms
[PASS] SAMPLE_06  | Type: digital_extortion      | Score:  83/100 (CRITICAL  ) | 0.08ms
[PASS] SAMPLE_07  | Type: credential_harvesting  | Score:  70/100 (HIGH RISK ) | 0.05ms
[PASS] SAMPLE_08  | Type: legitimate_flight_ticket | Score:  10/100 (LOW RISK  ) | 0.06ms
[PASS] SAMPLE_09  | Type: legitimate_bank_otp    | Score:  40/100 (SUSPICIOUS) | 0.05ms
[PASS] SAMPLE_10  | Type: legitimate_delivery    | Score:  10/100 (LOW RISK  ) | 0.11ms
----------------------------------------------------------------------
Overall Classification Accuracy : 100.0% (10/10)
Average Inference Latency       : 0.12 ms per scan (100% On-Device)
Deterministic Explainability    : 100% (Every score mapped to human reason)
======================================================================
```

---

### Option 5: Build & Install the Android APK

1. **Pre-built APK:** A verified standalone binary is ready in [`release/ScamHunt-final.apk`](release/ScamHunt-final.apk).
2. **Build from Source:**
   ```bash
   cd android
   ./gradlew assembleRelease
   ```
   The compiled APK will be generated at `android/app/build/outputs/apk/release/app-release-unsigned.apk`.

---

## 🔒 Security & Legal Evidence Architecture

### Section 65B Indian Evidence Act Compliance
In accordance with Section 65B of the Indian Evidence Act, 1872 and Section 63 of the Bharatiya Sakshya Adhiniyam, 2023:
- Cryptographic SHA-256 hashes are calculated on-device at the moment of evidence capture.
- Generates an untampered chain-of-custody envelope with UTC ISO 8601 timestamps and device identifiers.
- Export formats:
  1. **Police Incident Dossier (.TXT):** Ready for direct copy/paste into [cybercrime.gov.in](https://cybercrime.gov.in).
  2. **JSON Forensic Package (.JSON):** Machine-readable structured evidence.
  3. **Printed Affidavit:** Formal documentation for judicial proceedings.
  4. **1930 Helpline Script:** Plain-language speaking points for calling 1930.

---

## 👥 Core Development Team (Team CyberNova)

- **Aman Meshram** — Frontend Lead (UI/UX Architecture, Component Design, Frontend Implementation)
- **Divya Khare** — Backend Lead (API Development, Heuristics, Database Architecture)
- **Aman Semil** — QA & Repository Manager (Testing, Validation, Git Management)
- **Radhika Parmar** — AI & Documentation Lead (Prompt Engineering, Legal Evidence Research, Code Review)
