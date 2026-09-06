"""
engine.py
=========
Core local "AI" analysis engine for ScamHunt.

This is a deterministic, explainable heuristic engine (no external API
required). It is intentionally NOT a black box: every point added to a
risk score is tied to a human-readable reason and an indicator tag, so
the rest of the application (and the user) can always see *why* a
verdict was reached.

If an external LLM/AI API key is configured (see ai_client.py), the
higher layers of the app may *augment* this engine's output with a
natural-language explanation, but the score/category/indicator logic
here is always computed locally and deterministically. This guarantees
the app still works fully offline and never fabricates a verdict it
cannot support.
"""

import re


# ============================================================
# COLORS (shared with UI)
# ============================================================

RISK_COLORS = {
    "LOW RISK": "#35F5A0",
    "SUSPICIOUS": "#FF9F43",
    "HIGH RISK": "#FF3864",
    "CRITICAL": "#FF3864",
}


# ============================================================
# KEYWORD DATABASE
# ============================================================

URGENCY = [
    "urgent", "immediately", "act now", "last warning", "final warning",
    "expires today", "right away", "within 24 hours", "act fast",
    "limited time", "immediate action required",
]

CREDENTIALS = [
    "otp", "pin", "password", "passcode", "cvv", "verification code",
    "security code", "one time password", "login details", "atm pin",
]

PAYMENT = [
    "pay now", "payment", "send money", "transfer", "upi",
    "processing fee", "gift card", "bitcoin", "crypto", "deposit",
    "wire transfer", "advance fee", "registration fee", "clearance fee",
]

PRIZE = [
    "won", "winner", "prize", "reward", "lottery", "jackpot",
    "cashback", "free gift", "congratulations", "selected winner",
]

IMPERSONATION = [
    "bank", "government", "police", "income tax", "amazon", "microsoft",
    "google", "apple", "sbi", "hdfc", "icici", "paytm", "phonepe",
    "aadhaar", "customs", "courier", "fedex", "dhl", "electricity board",
]

ACCOUNT = [
    "account suspended", "account blocked", "account closed",
    "verify your account", "verify account", "reactivate",
    "unlock account", "kyc", "account will be deactivated",
]

PERSONAL = [
    "aadhaar", "aadhar", "pan number", "date of birth", "dob",
    "bank details", "card number", "personal details", "identity proof",
    "ssn", "social security",
]

REMOTE_ACCESS = [
    "anydesk", "teamviewer", "remote access", "screen sharing",
    "download apk", "install this app", "install application",
    "quicksupport", "screen share",
]

STALKING = [
    "i know where you live", "i know where you are", "where you live",
    "i am watching you", "i will find you", "cannot hide",
    "keep messaging", "keep contacting", "different accounts",
    "following you", "i see everything you do",
]

BULLYING = [
    "loser", "everyone hates you", "worthless", "useless",
    "nobody likes you", "idiot", "stupid", "embarrass you",
    "humiliate you", "kill yourself", "no one cares about you",
]

THREATS = [
    "i will hurt you", "i will harm you", "you are not safe",
    "i will come for you", "i will destroy you", "i will find you",
    "make you regret", "you will pay for this", "watch your back",
]

EXTORTION = [
    "blackmail", "ransom", "pay or else", "send money or",
    "i will expose you", "i will expose", "leak your photos",
    "release the video", "share your pictures",
]

SURVEILLANCE = [
    "spyware", "keylogger", "spying", "surveillance", "monitoring",
    "tracking", "track your phone", "remote access", "hidden camera",
    "read your messages",
]

MALWARE_HINT = [
    "click to update", "enable macros", "enable content",
    "run this file", "disable antivirus", "disable windows defender",
]

JOB_INVESTMENT = [
    "work from home", "earn daily", "guaranteed returns",
    "double your money", "investment opportunity", "part time job",
    "easy money", "no experience needed", "task based job",
    "guaranteed profit",
]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly", "rebrand.ly", "shorturl.at"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".zip", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".loan"]

CATEGORY_HINTS = {
    "PAYMENT FRAUD": "FINANCIAL SCAM",
    "PRIZE SCAM": "LOTTERY/PRIZE SCAM",
}


# ============================================================
# HELPERS
# ============================================================

def find_matches(text, words):
    text = text.lower()
    return [w for w in words if w.lower() in text]


def extract_urls(text):
    return re.findall(r"https?://[^\s\)\]\}\"'<>]+", text, re.IGNORECASE)


def extract_emails(text):
    return re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)


def extract_phones(text):
    # loose international/India style phone number matcher
    return re.findall(r"(?:\+?\d{1,3}[\s\-]?)?\d{10}\b", text)


def extract_upi_ids(text):
    return re.findall(r"\b[\w.\-]{2,256}@[a-zA-Z]{2,64}\b", text)


def get_domain(url):
    m = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
    if not m:
        return ""
    host = m.group(1)
    host = host.split("@")[-1]  # strip userinfo
    host = host.split(":")[0]   # strip port
    return host.lower()


def analyze_url_indicators(url):
    """Return (score_delta, indicators, categories, reasons) for a single URL."""
    score = 0
    indicators, categories, reasons = [], [], []
    u = url.lower()
    domain = get_domain(url)

    if re.search(r"https?://\d+\.\d+\.\d+\.\d+", u):
        score += 25
        indicators.append("IP-BASED URL")
        categories.append("PHISHING")
        reasons.append("URL uses a raw IP address instead of a normal domain name.")

    if any(x in u for x in URL_SHORTENERS):
        score += 18
        indicators.append("URL SHORTENER")
        categories.append("PHISHING")
        reasons.append("URL shortener hides the true destination of the link.")

    if any(domain.endswith(x) for x in SUSPICIOUS_TLDS):
        score += 18
        indicators.append("SUSPICIOUS DOMAIN")
        categories.append("PHISHING")
        reasons.append(f"Domain uses a top-level domain ({domain.split('.')[-1] if domain else '?'}) frequently abused for scam sites.")

    if not u.startswith("https://"):
        score += 8
        indicators.append("NO HTTPS")
        categories.append("PHISHING")
        reasons.append("Link does not use HTTPS encryption.")

    if domain.count("-") >= 2 or domain.count(".") >= 3:
        score += 10
        indicators.append("COMPLEX/HYPHENATED DOMAIN")
        categories.append("PHISHING")
        reasons.append("Domain name is unusually long/complex, a pattern often used to imitate legitimate brands.")

    for brand in ["paypal", "amazon", "google", "microsoft", "apple", "sbi", "hdfc", "icici", "paytm", "netflix"]:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            score += 20
            indicators.append("BRAND LOOK-ALIKE DOMAIN")
            categories.append("IDENTITY IMPERSONATION")
            reasons.append(f"Domain references the brand '{brand}' but is not that brand's official domain.")
            break

    return score, indicators, categories, reasons


def risk_level_from_score(score):
    if score >= 75:
        return "CRITICAL", RISK_COLORS["CRITICAL"]
    if score >= 55:
        return "HIGH RISK", RISK_COLORS["HIGH RISK"]
    if score >= 30:
        return "SUSPICIOUS", RISK_COLORS["SUSPICIOUS"]
    return "LOW RISK", RISK_COLORS["LOW RISK"]


def recommended_action(level):
    return {
        "CRITICAL": "DO NOT CLICK • DO NOT PAY • DO NOT SHARE OTP/PIN • PRESERVE EVIDENCE • CONSIDER REPORTING",
        "HIGH RISK": "DO NOT CLICK • DO NOT PAY • DO NOT SHARE OTP/PIN • PRESERVE EVIDENCE",
        "SUSPICIOUS": "PAUSE • VERIFY THE SOURCE INDEPENDENTLY • PRESERVE RELEVANT EVIDENCE",
        "LOW RISK": "NO STRONG THREAT PATTERN DETECTED • REMAIN CAUTIOUS",
    }.get(level, "PAUSE AND VERIFY BEFORE ACTING")


# ============================================================
# MAIN TEXT ANALYSIS
# ============================================================

def analyze(text):
    """
    Analyze a free-text message (SMS/WhatsApp/email body/social message/etc.)
    Returns a dict with score, level, color, categories, indicators, reasons,
    action, urls, emails, phones, upi candidates.
    """
    score = 0
    indicators, categories, reasons = [], [], []
    lower = text.lower()

    rule_table = [
        (URGENCY, 18, "URGENCY", "SOCIAL ENGINEERING", "Urgent or pressure-based language detected."),
        (CREDENTIALS, 30, "CREDENTIAL REQUEST", "CREDENTIAL THEFT", "Sensitive authentication information is requested."),
        (PAYMENT, 23, "PAYMENT REQUEST", "PAYMENT FRAUD", "Potential payment or money-transfer request detected."),
        (PRIZE, 20, "PRIZE CLAIM", "PRIZE SCAM", "Unexpected prize or reward claim detected."),
        (IMPERSONATION, 10, "IMPERSONATION", "IDENTITY IMPERSONATION", "Message references a potentially impersonated organization."),
        (ACCOUNT, 20, "ACCOUNT PRESSURE", "PHISHING", "Account suspension or verification pressure detected."),
        (PERSONAL, 20, "DATA HARVESTING", "IDENTITY THEFT", "Personal or identity information is being requested."),
        (REMOTE_ACCESS, 30, "REMOTE ACCESS", "MALWARE / REMOTE ACCESS", "Potentially dangerous remote-access software request detected."),
        (STALKING, 30, "CYBERSTALKING", "CYBERSTALKING", "Persistent or targeted stalking behavior detected."),
        (BULLYING, 22, "CYBERBULLYING", "CYBERBULLYING", "Targeted abusive or humiliating language detected."),
        (THREATS, 35, "THREAT", "ONLINE THREAT", "Potential threat or intimidation detected."),
        (EXTORTION, 30, "EXTORTION", "EXTORTION", "Potential blackmail or extortion pattern detected."),
        (SURVEILLANCE, 25, "SURVEILLANCE", "SUSPECTED SURVEILLANCE", "Potential digital surveillance indicator detected."),
        (MALWARE_HINT, 25, "MALWARE LURE", "MALWARE / SUSPICIOUS FILE", "Message pressures the user to disable security or run content."),
        (JOB_INVESTMENT, 20, "JOB/INVESTMENT LURE", "INVESTMENT SCAM", "Unrealistic job or investment offer pattern detected."),
    ]

    for words, pts, ind, cat, reason in rule_table:
        if find_matches(lower, words):
            score += pts
            indicators.append(ind)
            categories.append(cat)
            reasons.append(reason)

    urls = extract_urls(text)
    for url in urls:
        s, ind, cat, rs = analyze_url_indicators(url)
        score += s
        indicators.extend(ind)
        categories.extend(cat)
        reasons.extend(rs)

    if len(set(indicators)) >= 3:
        score += 12
        indicators.append("MULTI-SIGNAL ATTACK")
        reasons.append("Multiple independent threat indicators detected in the same message.")

    score = max(0, min(100, score))
    categories = list(dict.fromkeys(categories)) or ["NO CLEAR THREAT CATEGORY"]
    indicators = list(dict.fromkeys(indicators))
    reasons = list(dict.fromkeys(reasons))

    level, color = risk_level_from_score(score)
    action = recommended_action(level)

    return {
        "score": score,
        "level": level,
        "color": color,
        "categories": categories,
        "indicators": indicators,
        "reasons": reasons,
        "action": action,
        "urls": urls,
        "emails": extract_emails(text),
        "phones": extract_phones(text),
    }


# ============================================================
# DEMO DATA (for quick UI testing)
# ============================================================

DEMO_MESSAGES = {
    "Bank Scam": (
        "URGENT! Your bank account will be suspended today. "
        "Verify your account immediately at https://secure-account.xyz/verify "
        "and enter your OTP and PIN."
    ),
    "Prize Scam": (
        "CONGRATULATIONS! You have won Rs 50,000! "
        "Claim your reward immediately at https://claim-reward.xyz/winner "
        "and pay Rs 499 processing fee."
    ),
    "Delivery Scam": (
        "Your package could not be delivered. "
        "Verify your address at https://delivery-update.xyz/verify "
        "to reschedule delivery."
    ),
    "Cyberstalking": (
        "Why are you ignoring me? I know where you live. "
        "I will keep messaging you from different accounts. You cannot hide from me."
    ),
    "Cyberbullying": (
        "Everyone should see this. You are a loser and everyone hates you. "
        "I will keep posting about you until you leave school."
    ),
    "Threat": (
        "I know where you live. You are not safe. "
        "I will find you and make you regret this."
    ),
    "Job Scam": (
        "Work from home and earn daily guaranteed profit! "
        "No experience needed, just pay a small registration fee to start."
    ),
    "Safe Message": (
        "Hi Rahul, our project meeting is tomorrow at 10 AM in Room 204. "
        "Please bring the presentation."
    ),
}
