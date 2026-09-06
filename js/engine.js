/**
 * ScamHunt 2.0 - Core Local Heuristic AI & Cryptographic Engine
 * Ported & enhanced from verified heuristic rule tables.
 * 100% deterministic, explainable, and offline-capable.
 */

const URGENCY = [
  "urgent", "immediately", "act now", "last warning", "final warning",
  "expires today", "right away", "within 24 hours", "act fast",
  "limited time", "immediate action required", "power cut tonight", "disconnect electricity",
  "electricity will be disconnected", "bill unpaid", "account blocked today"
];

const CREDENTIALS = [
  "otp", "pin", "password", "passcode", "cvv", "verification code",
  "security code", "one time password", "login details", "atm pin", "netbanking password"
];

const PAYMENT = [
  "pay now", "payment", "send money", "transfer", "upi",
  "processing fee", "gift card", "bitcoin", "crypto", "deposit",
  "wire transfer", "advance fee", "registration fee", "clearance fee",
  "refundable deposit", "pay tm", "google pay", "phonepe"
];

const PRIZE = [
  "won", "winner", "prize", "reward", "lottery", "jackpot",
  "cashback", "free gift", "congratulations", "selected winner",
  "kbc lottery", "lucky draw", "claim 25 lakh", "claim prize"
];

const IMPERSONATION = [
  "bank", "government", "police", "income tax", "amazon", "microsoft",
  "google", "apple", "sbi", "hdfc", "icici", "paytm", "phonepe",
  "aadhaar", "customs", "courier", "fedex", "dhl", "electricity board",
  "cbi", "trai", "rbi", "cyber crime cell", "customs officer"
];

const ACCOUNT = [
  "account suspended", "account blocked", "account closed",
  "verify your account", "verify account", "reactivate",
  "unlock account", "kyc", "account will be deactivated",
  "pan not linked", "update pan immediately", "sim card blocked"
];

const PERSONAL = [
  "aadhaar", "aadhar", "pan number", "date of birth", "dob",
  "bank details", "card number", "personal details", "identity proof",
  "ssn", "social security", "mother maiden name"
];

const REMOTE_ACCESS = [
  "anydesk", "teamviewer", "remote access", "screen sharing",
  "download apk", "install this app", "install application",
  "quicksupport", "screen share", "rustdesk", "airmirror"
];

const EXTORTION = [
  "blackmail", "ransom", "pay or else", "send money or",
  "i will expose you", "i will expose", "leak your photos",
  "release the video", "share your pictures", "recorded on webcam",
  "send to your family", "pay 50000"
];

const JOB_INVESTMENT = [
  "work from home", "earn daily", "guaranteed returns",
  "double your money", "investment opportunity", "part time job",
  "easy money", "no experience needed", "task based job",
  "guaranteed profit", "like youtube videos", "telegram task"
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly", "rebrand.ly", "shorturl.at"
];

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".click", ".zip", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".loan", ".club", ".icu", ".vip"
];

class ThreatEngine {
  /**
   * Computes SHA-256 hex string using browser Web Crypto API
   */
  static async computeSHA256(content) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    } catch (e) {
      // Fallback simple hash if crypto is not available
      let hash = 0;
      for (let i = 0; i < content.length; i++) {
        hash = (hash << 5) - hash + content.charCodeAt(i);
        hash |= 0;
      }
      return "fallback_" + Math.abs(hash).toString(16).padStart(16, "0");
    }
  }

  static extractUrls(text) {
    const regex = /(https?:\/\/[^\s)\]}"'<>]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\/[^\s)\]}"'<>]*)/gi;
    const matches = text.match(regex);
    return matches ? Array.from(new Set(matches)) : [];
  }

  static extractPhones(text) {
    const regex = /(?:\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}|\b\d{10}\b/g;
    const matches = text.match(regex);
    return matches ? Array.from(new Set(matches)) : [];
  }

  static extractUpiIds(text) {
    const regex = /\b[\w.-]{2,256}@[a-zA-Z]{2,64}\b/g;
    const matches = text.match(regex);
    return matches ? Array.from(new Set(matches)) : [];
  }

  static getDomain(url) {
    let clean = url.trim().toLowerCase();
    if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
      clean = "http://" + clean;
    }
    try {
      const parsed = new URL(clean);
      return parsed.hostname;
    } catch {
      const match = clean.match(/https?:\/\/([^/?#]+)/i);
      return match ? match[1] : clean;
    }
  }

  static analyzeUrl(url) {
    let score = 0;
    const indicators = [];
    const categories = ["PHISHING"];
    const reasons = [];
    const u = url.toLowerCase();
    const domain = this.getDomain(url);

    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
      score += 25;
      indicators.push("RAW IP DESTINATION");
      reasons.push("URL uses an IP address directly instead of a verified registered domain.");
    }

    if (URL_SHORTENERS.some(s => u.includes(s))) {
      score += 20;
      indicators.push("URL SHORTENER OBFUSCATION");
      reasons.push("Shortened link masks the real landing destination, hiding fraud.");
    }

    if (SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld))) {
      score += 20;
      indicators.push("HIGH-RISK TLD");
      reasons.push(`Domain ends with an extension commonly abused by malicious threat actors.`);
    }

    if (!u.startsWith("https://") && !u.includes("bit.ly")) {
      score += 10;
      indicators.push("INSECURE PROTOCOL (NO HTTPS)");
      reasons.push("Traffic to this site lacks TLS encryption standards.");
    }

    if (domain.split("-").length >= 3 || domain.split(".").length >= 4) {
      score += 15;
      indicators.push("DECEPTIVE SUBDOMAIN SPOOF");
      reasons.push("Multiple hyphens or excessive subdomains mimic legitimate banking portals.");
    }

    const brands = ["sbi", "hdfc", "icici", "amazon", "paytm", "google", "microsoft", "apple", "netflix"];
    for (const b of brands) {
      if (domain.includes(b) && !domain.endsWith(`${b}.com`) && !domain.endsWith(`${b}.in`) && !domain.endsWith(`${b}.co.in`)) {
        score += 25;
        indicators.push(`IMPERSONATION: ${b.toUpperCase()}`);
        categories.push("IDENTITY IMPERSONATION");
        reasons.push(`Domain references brand '${b}' but is not an official registered brand domain.`);
        break;
      }
    }

    return { score, indicators, categories, reasons, domain };
  }

  static analyzeText(text) {
    let score = 0;
    const indicators = [];
    const categories = [];
    const reasons = [];
    const lower = text.toLowerCase();

    const rules = [
      { words: URGENCY, pts: 20, ind: "URGENT PRESSURE LURE", cat: "SOCIAL ENGINEERING", reason: "Creates extreme psychological panic or artificial time urgency." },
      { words: CREDENTIALS, pts: 35, ind: "AUTHENTICATION CREDENTIAL THEFT", cat: "CREDENTIAL THEFT", reason: "Directly requests confidential OTPs, passwords, or PINs." },
      { words: PAYMENT, pts: 22, ind: "DIRECT PAYMENT DEMAND", cat: "FINANCIAL FRAUD", reason: "Coerces rapid digital payment, fee transfer, or deposit." },
      { words: PRIZE, pts: 22, ind: "UNREALISTIC PRIZE / LOTTERY", cat: "LOTTERY / PRIZE SCAM", reason: "Promises high rewards or fake lottery winnings with zero prior entry." },
      { words: IMPERSONATION, pts: 15, ind: "AUTHORITY / INSTITUTION IMPERSONATION", cat: "IDENTITY IMPERSONATION", reason: "Impersonates reputable banks, law enforcement, or utility services." },
      { words: ACCOUNT, pts: 25, ind: "ACCOUNT SUSPENSION THREAT", cat: "PHISHING", reason: "Threatens immediate deactivation or blocking of bank accounts/SIM cards." },
      { words: PERSONAL, pts: 18, ind: "IDENTITY DATA HARVESTING", cat: "DATA HARVESTING", reason: "Demands sensitive identity identifiers (Aadhaar, PAN, Card details)." },
      { words: REMOTE_ACCESS, pts: 35, ind: "MALICIOUS REMOTE ACCESS APPLICATION", cat: "DEVICE COMPROMISE", reason: "Instructs user to install Screen Share / Remote Control APKs (AnyDesk, QuickSupport)." },
      { words: EXTORTION, pts: 35, ind: "DIGITAL EXTORTION / BLACKMAIL", cat: "EXTORTION & THREATS", reason: "Threatens leakage of compromised private media or reputation damage." },
      { words: JOB_INVESTMENT, pts: 20, ind: "TASK / INVESTMENT FRAUD LURE", cat: "INVESTMENT FRAUD", reason: "Offers guaranteed returns, part-time daily tasks, or double money schemes." }
    ];

    for (const rule of rules) {
      const match = rule.words.some(w => lower.includes(w));
      if (match) {
        score += rule.pts;
        indicators.push(rule.ind);
        categories.push(rule.cat);
        reasons.push(rule.reason);
      }
    }

    const urls = this.extractUrls(text);
    for (const url of urls) {
      const urlResult = this.analyzeUrl(url);
      score += urlResult.score;
      indicators.push(...urlResult.indicators);
      categories.push(...urlResult.categories);
      reasons.push(...urlResult.reasons);
    }

    const upis = this.extractUpiIds(text);
    if (upis.length > 0) {
      indicators.push("EMBEDDED UPI ID DETECTED");
      score += 10;
      reasons.push(`Contains payment handle (${upis[0]}), typical of unverified peer-to-peer scams.`);
    }

    if (new Set(indicators).size >= 3) {
      score += 15;
      indicators.push("MULTI-VECTOR COMPOUND ATTACK");
      reasons.push("Message synthesizes urgency, authority claims, and credential lures simultaneously.");
    }

    // Clamp score 0 - 100
    score = Math.max(0, Math.min(100, score));

    const uniqueCategories = Array.from(new Set(categories));
    const uniqueIndicators = Array.from(new Set(indicators));
    const uniqueReasons = Array.from(new Set(reasons));

    let level = "LOW RISK";
    let color = "#0d8a4e";
    let badgeClass = "bg-emerald-100 text-emerald-800 border-emerald-300";
    let gaugeColor = "#0d8a4e";

    if (score >= 70) {
      level = "HIGH RISK";
      color = "#ba1a1a";
      badgeClass = "bg-error-container text-on-error-container border-error";
      gaugeColor = "#ba1a1a";
    } else if (score >= 35) {
      level = "SUSPICIOUS";
      color = "#eab308";
      badgeClass = "bg-yellow-100 text-yellow-900 border-yellow-300";
      gaugeColor = "#eab308";
    }

    return {
      score,
      level,
      color,
      badgeClass,
      gaugeColor,
      categories: uniqueCategories.length > 0 ? uniqueCategories : ["NO DIRECT PATTERN"],
      indicators: uniqueIndicators,
      reasons: uniqueReasons,
      urls,
      upis,
      phones: this.extractPhones(text),
      timestamp: new Date().toISOString()
    };
  }
}

window.ThreatEngine = ThreatEngine;
