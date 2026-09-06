/**
 * ScamHunt 2.0 - Case Manager & Chain of Custody Storage
 * Manages incident dossiers, digital evidence hashes, and official cybercrime report exports.
 */

class CaseManager {
  static STORAGE_KEY = "scamhunt_cases_v2";
  static ACTIVE_CASE_KEY = "scamhunt_active_case_id";

  static generateCaseId() {
    const year = new Date().getFullYear();
    const rand = Math.floor(100000 + Math.random() * 900000);
    return `SC-${year}-${rand}`;
  }

  static getCases() {
    try {
      const data = localStorage.getItem(this.STORAGE_KEY);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  }

  static saveCases(cases) {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(cases));
    } catch (e) {
      console.error("Failed to save cases to localStorage:", e);
    }
  }

  static getActiveCase() {
    const cases = this.getCases();
    const activeId = localStorage.getItem(this.ACTIVE_CASE_KEY);
    if (activeId) {
      const found = cases.find(c => c.id === activeId);
      if (found) return found;
    }
    // Default or seed if none exists
    if (cases.length > 0) return cases[0];
    return this.createCase("Initial Incident Observation", "Initial suspicious message observed on SMS/WhatsApp.");
  }

  static setActiveCaseId(caseId) {
    localStorage.setItem(this.ACTIVE_CASE_KEY, caseId);
  }

  static createCase(title, description, analysisData = null, originalContent = "") {
    const cases = this.getCases();
    const caseId = this.generateCaseId();
    const now = new Date();

    const newCase = {
      id: caseId,
      title: title || `Incident ${caseId}`,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      status: "OPEN_INVESTIGATION",
      riskLevel: analysisData ? analysisData.level : "SUSPICIOUS",
      riskScore: analysisData ? analysisData.score : 65,
      categories: analysisData ? analysisData.categories : ["PHISHING / IMPERSONATION"],
      description: description || "Suspicious digital incident flagged by user.",
      incidentDetails: {
        description: description || "",
        dateTime: "",
        transactionId: "",
        phoneNumber: "",
        upiId: "",
        notes: ""
      },
      originalContent: originalContent,
      evidence: [],
      timeline: [
        {
          timestamp: now.toISOString(),
          event: "Case opened and forensic docket initialized."
        }
      ],
      checklist: {
        severContact: false,
        freezeAccounts: false,
        preserveEvidence: true,
        reportHelpline1930: false,
        fileCyberPortal: false
      }
    };

    if (originalContent) {
      // Async hash will be added
      newCase.evidence.push({
        id: `EV-${Date.now()}`,
        type: "SUSPICIOUS_TEXT",
        content: originalContent,
        timestamp: now.toISOString(),
        hash: "CALCULATING...",
        verified: true
      });
    }

    cases.unshift(newCase);
    this.saveCases(cases);
    this.setActiveCaseId(caseId);

    // Compute hash in background and update
    if (originalContent && window.ThreatEngine) {
      window.ThreatEngine.computeSHA256(originalContent).then(hash => {
        const updatedCases = CaseManager.getCases();
        const target = updatedCases.find(c => c.id === caseId);
        if (target && target.evidence[0]) {
          target.evidence[0].hash = hash;
          target.evidenceSha256 = hash;
          CaseManager.saveCases(updatedCases);
          if (window.renderEvidenceScreen) window.renderEvidenceScreen();
        }
      });
    }

    return newCase;
  }

  static async addEvidence(caseId, type, content, metadata = {}) {
    const cases = this.getCases();
    const target = cases.find(c => c.id === caseId);
    if (!target) return null;

    const hash = window.ThreatEngine ? await window.ThreatEngine.computeSHA256(content) : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const now = new Date();

    const evItem = {
      id: `EV-${Date.now()}`,
      type: type || "DIGITAL_EVIDENCE",
      content: content,
      timestamp: now.toISOString(),
      hash: hash,
      metadata: metadata,
      verified: true
    };

    target.evidence.push(evItem);
    target.timeline.push({
      timestamp: now.toISOString(),
      event: `Saved proof added: ${type}.`
    });
    target.updatedAt = now.toISOString();

    this.saveCases(cases);
    return evItem;
  }

  static updateChecklist(caseId, key, value) {
    const cases = this.getCases();
    const target = cases.find(c => c.id === caseId);
    if (target) {
      if (!target.checklist) target.checklist = {};
      target.checklist[key] = value;
      target.timeline.push({
        timestamp: new Date().toISOString(),
        event: `Containment step '${key}' marked as ${value ? 'COMPLETED' : 'PENDING'}.`
      });
      this.saveCases(cases);
    }
  }

  /**
   * Generates formal Incident Evidence Report for Police / Cyber Crime Cell
   */
  static generateReportText(c) {
    return `================================================================================
          SCAMHUNT DIGITAL CRIME EVIDENCE & INCIDENT DOSSIER
================================================================================
CASE REFERENCE NUMBER : ${c.id}
DATE RECORDED         : ${new Date(c.createdAt).toLocaleString()}
LAST UPDATED          : ${new Date(c.updatedAt).toLocaleString()}
INVESTIGATION STATUS  : ${c.status}

--------------------------------------------------------------------------------
1. THREAT CLASSIFICATION & RISK ASSESSMENT
--------------------------------------------------------------------------------
OVERALL THREAT VERDICT : ${c.riskLevel} (${c.riskScore}/100)
PRIMARY CATEGORIES     : ${c.categories.join(", ")}
CASE SUMMARY           : ${(c.incidentDetails && c.incidentDetails.description) || c.description}
DATE & TIME            : ${(c.incidentDetails && c.incidentDetails.dateTime) || new Date(c.createdAt).toLocaleString()}
TRANSACTION ID / UTR   : ${(c.incidentDetails && c.incidentDetails.transactionId) || "Not provided"}
SCAMMER PHONE NUMBER   : ${(c.incidentDetails && c.incidentDetails.phoneNumber) || "Not provided"}
UPI ID                 : ${(c.incidentDetails && c.incidentDetails.upiId) || "Not provided"}
ADDITIONAL NOTES       : ${(c.incidentDetails && c.incidentDetails.notes) || "None"}

--------------------------------------------------------------------------------
2. PRIMARY OFFENDING ARTIFACT / TRANSMISSION
--------------------------------------------------------------------------------
RAW PAYLOAD / CONTENT  :
${c.originalContent || "No direct text payload recorded."}

3. SAVED PROOF
--------------------------------------------------------------------------------
${c.evidence.map((e, idx) => `[ITEM ${idx + 1}] TYPE: ${e.type}
DATE & TIME : ${new Date(e.timestamp).toLocaleString()}
FILE / DETAILS : ${e.metadata && e.metadata.fileName ? e.metadata.fileName : e.content}
`).join("\n--------------------------------------------------------------------------------\n")}

--------------------------------------------------------------------------------
4. INCIDENT TIMELINE & ACTIONS LOG
--------------------------------------------------------------------------------
${c.timeline.map(t => `[${new Date(t.timestamp).toLocaleTimeString()}] ${t.event}`).join("\n")}

--------------------------------------------------------------------------------
5. RECOMMENDED IMMEDIATE POLICE / BANK ESCALATION ACTIONS
--------------------------------------------------------------------------------
* National Cyber Crime Reporting Portal: https://cybercrime.gov.in
* National Emergency Cyber Helpline: Dial 1930
* Bank Account / UPI Freeze: Request immediate transaction recall within 24h.
* Keep screenshots, messages, payment records, and other saved proof unchanged.

Generated by ScamHunt 2.0 Mobile Threat Defense Suite
================================================================================`;
  }
}

window.CaseManager = CaseManager;
