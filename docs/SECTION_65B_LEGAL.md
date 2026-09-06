# Section 65B Legal Evidence Stamping & Indian Cyber Law Compliance

## Legal Context

Under **Section 65B of the Indian Evidence Act, 1872** (and **Section 63 of the Bharatiya Sakshya Adhiniyam, 2023**), electronic records are admissible in a court of law only if the integrity of the electronic output can be conclusively demonstrated:

1. The electronic record was produced by the computer during the period over which the computer was used regularly.
2. During the said period, information of the kind contained in the electronic record was regularly fed into the computer in the ordinary course of the said activities.
3. The computer was operating properly or the operation did not affect the accuracy of the electronic record.
4. The information contained in the electronic record reproduces or is derived from such information fed into the computer in the ordinary course of said activities.

---

## How ScamHunt 2.0 Enforces Section 65B Compliance

```
[Incoming Suspicious Message / Screenshot / File]
                        │
                        ▼
   [Client-Side Cryptographic Hash Generation]
         SHA-256 (256-bit Digest)
                        │
                        ▼
       [Tamper-Proof Metadata Envelope]
  • Unique Case Identifier: SC-2026-XXXXXX
  • ISO 8601 UTC Timestamp: YYYY-MM-DDTHH:MM:SS.sssZ
  • Chain of Custody Device Hash: SHA-256
  • Forensic Integrity Seal: SHA-256
                        │
                        ▼
    [Direct Export to Official Evidence Package]
  1. Plaintext Police Incident Dossier (.TXT)
  2. Machine-Readable Digital Evidence Package (.JSON)
  3. Printed Formal Court Affidavit (.PDF)
  4. 1930 Cyber Crime Helpline Operator Script
```

### Key Technical Safeguards

- **Zero Cloud Modification:** Hashing is executed **entirely inside the victim's device** using the browser's native `crypto.subtle.digest('SHA-256')` or Python's `hashlib.sha256`. No remote server can alter the file or timestamp.
- **Deterministic Checksums:** Anyone inspecting the evidence file (law enforcement, forensic analysts, defense counsel) can recompute the SHA-256 hash using standard tools (`shasum -a 256` or PowerShell `Get-FileHash`) to verify it matches the stamped dossier.
- **Immediate Containment:** Generates an incident dossier ready for direct submission to the **National Cyber Crime Reporting Portal** (`cybercrime.gov.in`) or via emergency hotline **1930**.
