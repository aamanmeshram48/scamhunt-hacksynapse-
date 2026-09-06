# ScamHunt 2.0 — Release Distribution

This directory contains the standalone compiled release binary for ScamHunt 2.0 Mobile Threat Defense.

## 📦 Artifact Details

- **Filename:** `ScamHunt-final.apk`
- **Application ID:** `com.scamhunt.app`
- **Version Code:** `3`
- **Version Name:** `3.0`
- **Min SDK:** Android 6.0 (API 23)
- **Target SDK:** Android 14 (API 34)
- **Architecture:** Universal (ARM64, ARMv7, x86_64)
- **File Size:** ~3.78 MB
- **SHA-256 Checksum:** `4051579e214783e73153831415f8cf6014987bf8e6fe2d96c8aecebdd5554ddd`

## 🛡️ Security & Privacy Characteristics

- **100% Offline-First:** Bundles all web UI, CSS styling, and JavaScript heuristic detection on-device in `assets/`.
- **Zero Cloud Uploads:** No user messages, screenshots, or personal data ever leave the device.
- **Section 65B Legal Evidence Stamping:** Integrated native Kotlin bridge (`AndroidFileSaver`) saves tamper-proof SHA-256 hashed incident reports directly to `Downloads/` via Android `MediaStore`.
- **Minimal Permissions:** Only standard network access for opening external verification resources (`android.permission.INTERNET`).

## 📲 Installation Instructions

1. Download or copy `ScamHunt-final.apk` to your Android device.
2. Open your device's File Manager and tap `ScamHunt-final.apk`.
3. If prompted, enable "Install unknown apps" for your file manager.
4. Tap **Install** and launch **ScamHunt**.
