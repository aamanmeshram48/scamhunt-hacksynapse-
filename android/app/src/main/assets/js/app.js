/**
 * ScamHunt 2.0 - Master Application Controller
 * Wires together the 8 Google Stitch screens, 6 threat inspection modalities, threat engine, and case manager.
 */

// Global State
const appState = {
  currentScreen: "screen-home",
  activeCase: null,
  currentAnalysis: null,
  viewMode: "frame", // 'frame' | 'desktop'
  scanTab: "message" // 'message' | 'url' | 'image' | 'file' | 'voice' | 'impersonation'
};

// Preset Threat Scenarios for all 6 modalities
const PRESET_SCENARIOS = {
  message: [
    {
      title: "⚡ Electricity Cut Scam",
      text: "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the electricity office because your previous month bill was not updated. Please immediately contact our power officer at 9876543210 or update bill at http://192.168.1.105/bses-bill.apk immediately to avoid disruption."
    },
    {
      title: "🏦 SBI KYC Suspension",
      text: "Dear SBI User, your State Bank of India account has been suspended today due to expired KYC documentation. Please click https://bit.ly/sbi-pan-kyc-update immediately to update your PAN and verify OTP to avoid permanent account deactivation."
    },
    {
      title: "💼 Telegram Task Job",
      text: "Congratulations! You have been selected for Amazon Online Part-time Job. Work from home 30 minutes daily and earn guaranteed Rs 5,000 to 20,000 daily. Just like YouTube videos. Send processing fee of Rs 500 to upi taskjob@okaxis to start immediately."
    },
    {
      title: "🎁 KBC 25 Lakh Lottery",
      text: "Dear winner, congratulations! Your mobile number won 25,00,000 Lakh in KBC Jio Lucky Draw 2026. To claim prize money, contact Rana Pratap Singh on WhatsApp at +91-9988776655 and send advance clearance fee."
    },
    {
      title: "🛡️ Legitimate Flight Ticket",
      text: "IndiGo Flight 6E-204 from New Delhi (DEL) to Bengaluru (BLR) is confirmed for 12 Sep at 14:15. Your PNR is Z8Y3X1. Check-in online at https://goindigo.in. Have a pleasant trip!"
    }
  ],
  url: [
    {
      title: "🚨 Fake Banking Portal",
      text: "http://192.168.4.15/sbi-online-kyc-login.html?user=verify"
    },
    {
      title: "⚠️ Bitly Disguised Link",
      text: "https://bit.ly/income-tax-refund-instant-approval-2026"
    },
    {
      title: "🚦 Fake Traffic Challan",
      text: "http://echallan-parivahan-delhi-police-fine.top/pay-mparivahan"
    }
  ],
  image: [
    {
      title: "🧾 Forged UPI Transfer Receipt",
      text: "PAYMENT SUCCESSFUL to Merchant RS 48,500. Transaction ID: UPI/20260905/981240. Status: Completed via FakePay App.",
      filename: "screenshot_upi_forgery_48500.png"
    },
    {
      title: "🎟️ Fake KBC Winning Certificate",
      text: "ALL INDIA LOTTERY COMMITTEE: Winner Certificate Number KBC-2026-9912. Tax clearance deposit required Rs 12,500.",
      filename: "kbc_lottery_winner_certificate.jpg"
    },
    {
      title: "⬛ Deceptive 'Receive Money' QR",
      text: "DECEPTIVE QR CODE SCAM: Scanning this QR will execute UPI Debit request 'upi://pay?pa=scammer@okaxis&am=5000' instead of crediting account.",
      filename: "fake_refund_qr_code.png"
    }
  ],
  file: [
    {
      title: "📦 Fake BSES Bill APK",
      text: "MALWARE APK DETECTED: bses_power_bill_payment_v3.apk - Contains Android RAT permissions (RECEIVE_SMS, READ_CONTACTS, ACCESSIBILITY_SERVICE).",
      filename: "bses_power_bill_payment.apk"
    },
    {
      title: "📄 Macro-Enabled Tax PDF",
      text: "SUSPICIOUS ATTACHMENT: Income_Tax_Notice_Urgent_Summons.pdf.exe - Double extension disguised executable payload.",
      filename: "Income_Tax_Notice.pdf.exe"
    },
    {
      title: "🎁 PM Kisan Yojana APK",
      text: "UNTRUSTED APKS: PM_Kisan_16th_Kist_Direct_Benefit.apk - Unsigned third party sideloaded banking trojan package.",
      filename: "PM_Kisan_16th_Kist.apk"
    }
  ],
  voice: [
    {
      title: "👮 Fake Police Arrest Audio",
      text: "VOICE CLONE DETECTED: 'This is Inspector Vikram Rathore from Mumbai Crime Branch. Your son has been arrested in a narcotics case. Send Rs 2,00,000 immediately to settle before court FIR.'",
      filename: "audio_police_extortion_call.wav"
    },
    {
      title: "⚖️ Digital Arrest CBI Threat",
      text: "SUSPECTED AI EXTORTION: 'CBI Cyber cell notice. You are under digital house arrest. Do not disconnect this Skype/WhatsApp call. Transfer all funds to RBI safety pool account.'",
      filename: "cbi_digital_arrest_notice.mp3"
    },
    {
      title: "👔 Deepfake CEO Emergency Wire",
      text: "DEEPFAKE VOICE CLONING: 'Hi Rahul, I am in an urgent confidential board meeting abroad. Need you to wire $25,000 to vendor account immediately. Email confirmation later.'",
      filename: "ceo_deepfake_audio_memo.wav"
    }
  ],
  impersonation: [
    {
      title: "🛡️ Fake Cyber Cell Inspector",
      text: "IMPERSONATION REPORT: Caller claiming to be 'Sub-Inspector Arvind Sharma, Cyber Crime Cell HQ, New Delhi' demanding OTP verification for banking security audit."
    },
    {
      title: "🏦 Fake Bank Fraud Officer",
      text: "IMPERSONATION REPORT: Caller from +91-9876543210 claiming to be 'HDFC Security Manager Mr. Kapoor' demanding remote AnyDesk app installation to prevent account freeze."
    },
    {
      title: "📡 TRAI Mobile Block Alert",
      text: "IMPERSONATION REPORT: Automated IVR call claiming 'Department of Telecommunications: Your Aadhaar has 9 illegal SIM cards. All phone numbers will be terminated within 2 hours. Press 9.'"
    }
  ]
};

// DOM Elements & Initialization
document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initAuthentication();

  // Initialize Case
  appState.activeCase = CaseManager.getActiveCase();

  // Wire Navigation
  initNavigation();

  // Wire Scanner & Modalities
  initScanner();

  // Wire Evidence Actions
  initEvidenceActions();

  // Wire Incident Checklist
  initIncidentChecklist();

  // Wire Viewport Mode Toggle
  initViewportControls();

  // Render initial components
  renderHome();
  renderUserProfile();
  renderEvidenceScreen();
  renderIncidentScreen();

  // Initial route
  const hasAccount = localStorage.getItem("scamhunt_account");
  const hasSession = localStorage.getItem("scamhunt_session") === "active";
  const hasVisited = localStorage.getItem("scamhunt_visited");
  if (hasSession || (!hasAccount && hasVisited)) {
    navigateTo("screen-home");
  } else if (hasAccount) {
    navigateTo("screen-auth");
  } else {
    navigateTo("screen-splash");
  }
});

function initTheme() {
  const savedTheme = localStorage.getItem("scamhunt_theme") || "system";
  applyTheme(savedTheme);
  document.querySelectorAll("[data-theme-option]").forEach(option => {
    option.addEventListener("change", () => {
      if (option.checked) {
        localStorage.setItem("scamhunt_theme", option.value);
        applyTheme(option.value);
      }
    });
  });
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  systemTheme.addEventListener?.("change", () => {
    if ((localStorage.getItem("scamhunt_theme") || "system") === "system") applyTheme("system");
  });
}

function applyTheme(theme) {
  const dark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
  document.querySelectorAll("[data-theme-option]").forEach(option => {
    option.checked = option.value === theme;
  });
}

function initAuthentication() {
  document.querySelectorAll("[data-toggle-password]").forEach(button => {
    button.addEventListener("click", () => {
      const input = document.getElementById(button.dataset.togglePassword);
      if (!input) return;
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
      const icon = button.querySelector(".material-symbols-outlined");
      if (icon) icon.textContent = showing ? "visibility" : "visibility_off";
    });
  });

  const signupForm = document.getElementById("signup-form");
  if (signupForm) {
    const signupPassword = document.getElementById("signup-password");
    const signupConfirmPassword = document.getElementById("signup-confirm-password");
    const createAccountButton = document.getElementById("btn-create-account");
    const signupSuccess = document.getElementById("signup-success");

    const updatePasswordGuide = () => {
      const password = signupPassword.value;
      const rules = {
        "password-rule-length": password.length >= 8,
        "password-rule-number": /\d/.test(password),
        "password-rule-special": /[^A-Za-z0-9]/.test(password)
      };
      Object.entries(rules).forEach(([id, satisfied]) => {
        const rule = document.getElementById(id);
        if (!rule) return;
        rule.classList.toggle("text-secondary", satisfied);
        const icon = rule.querySelector(".material-symbols-outlined");
        if (icon) icon.textContent = satisfied ? "check_circle" : "radio_button_unchecked";
      });
    };

    signupPassword.addEventListener("input", updatePasswordGuide);
    signupConfirmPassword.addEventListener("input", () => {
      document.getElementById("signup-confirm-error").classList.toggle("hidden", !signupConfirmPassword.value || signupPassword.value === signupConfirmPassword.value);
    });
    signupForm.querySelectorAll("input").forEach(input => {
      input.addEventListener("focus", () => {
        setTimeout(() => input.scrollIntoView({ behavior: "smooth", block: "center" }), 120);
      });
    });

    signupForm.addEventListener("submit", event => {
      event.preventDefault();
      const values = {
        name: document.getElementById("signup-name").value.trim(),
        userId: document.getElementById("signup-user-id").value.trim(),
        email: document.getElementById("signup-email").value.trim(),
        password: document.getElementById("signup-password").value,
        confirmPassword: document.getElementById("signup-confirm-password").value
      };
      const errors = {
        name: !values.name,
        userId: !/^[A-Za-z0-9._-]{3,24}$/.test(values.userId),
        email: !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email),
        password: values.password.length < 8 || !/\d/.test(values.password) || !/[^A-Za-z0-9]/.test(values.password),
        confirm: !values.confirmPassword || values.password !== values.confirmPassword
      };
      const userIdError = document.getElementById("signup-user-id-error");
      const passwordError = document.getElementById("signup-password-error");
      userIdError.textContent = values.userId ? "User ID can use letters, numbers, dots, underscores, or hyphens." : "Please choose a User ID.";
      passwordError.textContent = "Password must contain at least 8 characters, one number, and one special character.";
      document.getElementById("signup-name-error").classList.toggle("hidden", !errors.name);
      document.getElementById("signup-user-id-error").classList.toggle("hidden", !errors.userId);
      document.getElementById("signup-email-error").classList.toggle("hidden", !errors.email);
      document.getElementById("signup-password-error").classList.toggle("hidden", !errors.password);
      document.getElementById("signup-confirm-error").classList.toggle("hidden", !errors.confirm);
      if (Object.values(errors).some(Boolean)) return;

      createAccountButton.disabled = true;
      createAccountButton.textContent = "Creating Account...";
      localStorage.setItem("scamhunt_account", JSON.stringify({name: values.name, userId: values.userId, email: values.email, password: values.password}));
      localStorage.setItem("scamhunt_session", "active");
      localStorage.setItem("scamhunt_visited", "1");
      signupSuccess.classList.remove("hidden");
      setTimeout(() => navigateTo("screen-home"), 700);
    });
  }

  const signInButton = document.getElementById("btn-sign-in");
  if (signInButton) {
    signInButton.addEventListener("click", () => {
      const userId = document.getElementById("auth-email").value.trim();
      const password = document.getElementById("auth-pin").value;
      const account = JSON.parse(localStorage.getItem("scamhunt_account") || "null");
      const userError = document.getElementById("auth-user-error");
      const passwordError = document.getElementById("auth-password-error");
      const loginError = document.getElementById("auth-login-error");
      userError.classList.toggle("hidden", !!userId);
      passwordError.classList.toggle("hidden", !!password);
      const valid = account && account.userId === userId && account.password === password;
      loginError.classList.toggle("hidden", !userId || !password || valid);
      if (!userId || !password || !valid) return;
      localStorage.setItem("scamhunt_session", "active");
      localStorage.setItem("scamhunt_visited", "1");
      navigateTo("screen-home");
    });
  }
}

/**
 * Screen Navigation Router
 */
function navigateTo(screenId) {
  const screens = document.querySelectorAll(".screen");
  screens.forEach(s => {
    s.classList.remove("active");
  });

  const target = document.getElementById(screenId);
  if (target) {
    target.classList.add("active");
    appState.currentScreen = screenId;

    // Scroll screens container to top cleanly
    const container = document.getElementById("screens-container");
    if (container) {
      container.scrollTop = 0;
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  // Update Bottom Nav active indicator
  updateNavIndicators(screenId);

  // Screen-specific updates
  if (screenId === "screen-home") {
    renderHome();
    renderUserProfile();
  } else if (screenId === "screen-profile") {
    renderUserProfile();
  } else if (screenId === "screen-evidence") {
    renderEvidenceScreen();
  } else if (screenId === "screen-incident") {
    renderIncidentScreen();
  }
}

function renderUserProfile() {
  let account = null;
  try {
    account = JSON.parse(localStorage.getItem("scamhunt_account") || "null");
  } catch {
    account = null;
  }

  const name = account?.name?.trim() || "Profile";
  const userId = account?.userId?.trim() || "";
  const email = account?.email?.trim() || "";
  const initials = name === "Profile"
    ? "SC"
    : name.split(/\s+/).filter(Boolean).slice(0, 2).map(part => part[0].toUpperCase()).join("");
  const greeting = document.getElementById("home-greeting");
  const profileName = document.getElementById("profile-full-name");
  const profileUserId = document.getElementById("profile-user-id");
  const profileEmail = document.getElementById("profile-email");
  const profileInitials = document.getElementById("profile-initials");
  if (greeting) greeting.textContent = account?.name ? `Hello, ${name}` : "Hello";
  if (profileName) profileName.textContent = name;
  if (profileUserId) profileUserId.textContent = userId ? `@${userId}` : "";
  if (profileEmail) profileEmail.textContent = email;
  if (profileInitials) profileInitials.textContent = initials;
}

window.navigateTo = navigateTo;

/**
 * Direct Shortcut to Inspection Checkers from Home
 */
function openChecker(modality) {
  navigateTo("screen-scan");
  switchScanTab(modality);
}
window.openChecker = openChecker;

/**
 * Meet the Developers Modal Handlers
 */
function openMeetDevelopers() {
  const modal = document.getElementById("modal-developers");
  if (modal) {
    modal.classList.remove("hidden");
    modal.classList.add("flex");
  }
}
window.openMeetDevelopers = openMeetDevelopers;

function closeMeetDevelopers() {
  const modal = document.getElementById("modal-developers");
  if (modal) {
    modal.classList.add("hidden");
    modal.classList.remove("flex");
  }
}
window.closeMeetDevelopers = closeMeetDevelopers;

function clearScanInput() {
  const input = document.getElementById("scan-input-text");
  if (input) input.value = "";
  const filename = document.getElementById("scan-dropzone-filename");
  if (filename) filename.classList.add("hidden");
}
window.clearScanInput = clearScanInput;

function updateNavIndicators(screenId) {
  const navBtns = document.querySelectorAll(".bottom-nav-btn");
  navBtns.forEach(btn => {
    const target = btn.getAttribute("data-target");
    const isProfileSubscreen = (screenId === "screen-developers" && target === "screen-profile");
    if (target === screenId || isProfileSubscreen) {
      btn.classList.add("text-secondary", "font-bold");
      btn.classList.remove("text-on-surface-variant");
      const icon = btn.querySelector(".material-symbols-outlined");
      if (icon) icon.style.fontVariationSettings = "'FILL' 1";
    } else {
      btn.classList.remove("text-secondary", "font-bold");
      btn.classList.add("text-on-surface-variant");
      const icon = btn.querySelector(".material-symbols-outlined");
      if (icon) icon.style.fontVariationSettings = "'FILL' 0";
    }
  });

  // Hide header & bottom bar on splash and auth screens
  const header = document.getElementById("main-header");
  const bottomNav = document.getElementById("bottom-nav");
  if (screenId === "screen-splash" || screenId === "screen-auth" || screenId === "screen-signup") {
    if (header) header.classList.add("hidden");
    if (bottomNav) bottomNav.classList.add("hidden");
  } else {
    if (header) header.classList.remove("hidden");
    if (bottomNav) bottomNav.classList.remove("hidden");
  }
}

function initNavigation() {
  document.querySelectorAll("[data-navigate]").forEach(el => {
    el.addEventListener("click", e => {
      e.preventDefault();
      const target = el.getAttribute("data-navigate");
      navigateTo(target);
    });
  });

  document.querySelectorAll(".bottom-nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.getAttribute("data-target");
      if (target) navigateTo(target);
    });
  });
}

function initViewportControls() {
  const frameBtn = document.getElementById("toggle-frame-mode");
  const desktopBtn = document.getElementById("toggle-desktop-mode");

  if (frameBtn) {
    frameBtn.addEventListener("click", () => {
      document.body.classList.remove("desktop-mode");
      document.body.classList.add("frame-mode");
      frameBtn.classList.add("bg-secondary", "text-white");
      desktopBtn.classList.remove("bg-secondary", "text-white");
      desktopBtn.classList.add("bg-surface-container-high", "text-on-surface");
    });
  }

  if (desktopBtn) {
    desktopBtn.addEventListener("click", () => {
      document.body.classList.remove("frame-mode");
      document.body.classList.add("desktop-mode");
      desktopBtn.classList.add("bg-secondary", "text-white");
      frameBtn.classList.remove("bg-secondary", "text-white");
      frameBtn.classList.add("bg-surface-container-high", "text-on-surface");
    });
  }
}

/**
 * Switch Scan Tab & Modality
 */
function switchScanTab(type) {
  appState.scanTab = type;
  const scanTabs = document.querySelectorAll(".scan-tab-btn");
  const inputArea = document.getElementById("scan-input-text");
  const label = document.getElementById("scan-input-label");
  const dropzone = document.getElementById("scan-media-dropzone");
  const voiceBox = document.getElementById("scan-voice-box");
  const dropzoneTitle = document.getElementById("scan-dropzone-title");
  const dropzoneSub = document.getElementById("scan-dropzone-sub");
  const dropzoneIcon = document.getElementById("scan-dropzone-icon");

  scanTabs.forEach(t => {
    if (t.getAttribute("data-tab") === type) {
      t.classList.remove("bg-surface-container", "text-on-surface-variant");
      t.classList.add("bg-secondary", "text-white");
    } else {
      t.classList.remove("bg-secondary", "text-white");
      t.classList.add("bg-surface-container", "text-on-surface-variant");
    }
  });

  // Contextual controls
  if (type === "url") {
    if (label) label.textContent = "Suspicious Link / URL Input";
    if (inputArea) inputArea.placeholder = "Paste suspicious link or domain (e.g. http://192.168.1.10/sbi-verify.xyz)...";
    if (dropzone) dropzone.classList.add("hidden");
    if (voiceBox) voiceBox.classList.add("hidden");
  } else if (type === "image") {
    if (label) label.textContent = "Screenshot / Image OCR Details";
    if (inputArea) inputArea.placeholder = "Extracted text from screenshot or description of receipt/QR banner...";
    if (dropzone) {
      dropzone.classList.remove("hidden");
      if (dropzoneTitle) dropzoneTitle.textContent = "Tap to upload Screenshot / QR / Receipt";
      if (dropzoneSub) dropzoneSub.textContent = "Supports PNG, JPG (Simulated OCR text extraction)";
      if (dropzoneIcon) dropzoneIcon.textContent = "image";
    }
    if (voiceBox) voiceBox.classList.add("hidden");
  } else if (type === "file") {
    if (label) label.textContent = "File / APK Attachment Details";
    if (inputArea) inputArea.placeholder = "Suspected APK package name, PDF filename, or attachment details...";
    if (dropzone) {
      dropzone.classList.remove("hidden");
      if (dropzoneTitle) dropzoneTitle.textContent = "Tap to upload APK / PDF for Static Analysis";
      if (dropzoneSub) dropzoneSub.textContent = "Inspects Android manifest permissions & macro scripts";
      if (dropzoneIcon) dropzoneIcon.textContent = "folder_zip";
    }
    if (voiceBox) voiceBox.classList.add("hidden");
  } else if (type === "voice") {
    if (label) label.textContent = "Voice Call Transcript & Spectral Log";
    if (inputArea) inputArea.placeholder = "Transcribed speech or description of extortion caller's demands...";
    if (dropzone) dropzone.classList.add("hidden");
    if (voiceBox) voiceBox.classList.remove("hidden");
  } else if (type === "impersonation") {
    if (label) label.textContent = "Official Identity & Caller Investigation";
    if (inputArea) inputArea.placeholder = "Enter caller name, claimed police badge number, agency, or bank department...";
    if (dropzone) dropzone.classList.add("hidden");
    if (voiceBox) voiceBox.classList.add("hidden");
  } else {
    // message
    if (label) label.textContent = "Suspicious Message Input";
    if (inputArea) inputArea.placeholder = "Paste suspicious SMS, WhatsApp message, email, job offer, or threat here...";
    if (dropzone) dropzone.classList.add("hidden");
    if (voiceBox) voiceBox.classList.add("hidden");
  }

  // Update Presets for this modality
  renderPresets(type);
}

function renderPresets(modality) {
  const chipsContainer = document.getElementById("preset-chips");
  const inputArea = document.getElementById("scan-input-text");
  const filenameBadge = document.getElementById("scan-dropzone-filename");

  if (!chipsContainer || !inputArea) return;
  chipsContainer.innerHTML = "";

  const presets = PRESET_SCENARIOS[modality] || PRESET_SCENARIOS.message;

  presets.forEach(data => {
    const chip = document.createElement("button");
    chip.className = "px-3 py-1.5 rounded-full text-xs font-semibold bg-surface-container-high hover:bg-secondary-fixed hover:text-on-secondary-fixed transition-all text-on-surface-variant flex items-center gap-1.5 shrink-0 active:scale-95";
    chip.innerHTML = `<span>${data.title}</span>`;
    chip.addEventListener("click", () => {
      inputArea.value = data.text;
      if (data.filename && filenameBadge) {
        filenameBadge.textContent = data.filename;
        filenameBadge.classList.remove("hidden");
      } else if (filenameBadge) {
        filenameBadge.classList.add("hidden");
      }
      inputArea.focus();
      inputArea.classList.add("ring-2", "ring-secondary");
      setTimeout(() => inputArea.classList.remove("ring-2", "ring-secondary"), 400);
    });
    chipsContainer.appendChild(chip);
  });
}

function initScanner() {
  const scanBtn = document.getElementById("btn-start-scan");
  const inputArea = document.getElementById("scan-input-text");
  const scanProgress = document.getElementById("scan-progress-box");
  const scanTabs = document.querySelectorAll(".scan-tab-btn");
  const dropzone = document.getElementById("scan-media-dropzone");
  const fileInput = document.getElementById("scan-file-input");
  const filenameBadge = document.getElementById("scan-dropzone-filename");

  // Tab switching
  scanTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const type = tab.getAttribute("data-tab");
      switchScanTab(type);
    });
  });

  // Initial presets render
  renderPresets("message");

  // Wire file dropzone
  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", e => {
      const file = e.target.files[0];
      if (file) {
        if (filenameBadge) {
          filenameBadge.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
          filenameBadge.classList.remove("hidden");
        }
        if (inputArea && !inputArea.value) {
          inputArea.value = `[Uploaded File: ${file.name}, MIME: ${file.type || 'application/octet-stream'}, Size: ${file.size} bytes]. Initiating heuristic static analysis.`;
        }
      }
    });
  }

  // Scan execution
  if (scanBtn && inputArea) {
    scanBtn.addEventListener("click", () => {
      const text = inputArea.value.trim();
      if (!text) {
        inputArea.focus();
        inputArea.classList.add("border-error");
        setTimeout(() => inputArea.classList.remove("border-error"), 600);
        return;
      }

      // Show scanning animation
      if (scanProgress) scanProgress.classList.remove("hidden");
      scanBtn.disabled = true;
      scanBtn.innerHTML = `<span class="material-symbols-outlined animate-spin text-[20px]">sync</span><span>Analyzing Heuristics...</span>`;

      setTimeout(() => {
        const result = ThreatEngine.analyzeText(text);
        appState.currentAnalysis = result;

        // Auto-create or associate with case
        const title = `Analysis: ${result.categories[0] || 'Digital Threat'}`;
        const newCase = CaseManager.createCase(title, `User scanned content via Scan Hub (${result.level})`, result, text);
        appState.activeCase = newCase;

        if (scanProgress) scanProgress.classList.add("hidden");
        scanBtn.disabled = false;
        scanBtn.innerHTML = `<span class="material-symbols-outlined text-[20px]">security</span><span>Analyze Threat Now</span>`;

        // Render Threat Analysis Screen
        renderThreatAnalysis(result, text);
        navigateTo("screen-analysis");
      }, 700);
    });
  }
}

/**
 * Threat Analysis Screen Renderer
 */
function renderThreatAnalysis(res, originalText) {
  const scoreEl = document.getElementById("threat-score-val");
  const gaugeCircle = document.getElementById("threat-gauge-circle");
  const levelBadge = document.getElementById("threat-level-badge");
  const riskSegments = {
    "LOW RISK": document.getElementById("risk-segment-safe"),
    "SUSPICIOUS": document.getElementById("risk-segment-suspicious"),
    "HIGH RISK": document.getElementById("risk-segment-high")
  };
  const categoryHeader = document.getElementById("threat-category-title");
  const sourceMessage = document.getElementById("threat-source-text");
  const indicatorsContainer = document.getElementById("threat-indicators-list");
  const actionBanner = document.getElementById("threat-action-banner");

  if (scoreEl) scoreEl.textContent = res.score;
  if (categoryHeader) categoryHeader.textContent = res.categories.join(" & ") || "Suspicious Threat Pattern";
  if (sourceMessage) sourceMessage.textContent = `“${originalText}”`;

  Object.values(riskSegments).forEach(segment => {
    if (segment) {
      segment.className = "flex-1 py-1 px-2 rounded-full text-on-surface-variant opacity-60";
    }
  });
  const selectedSegment = riskSegments[res.level];
  if (selectedSegment) {
    selectedSegment.className = "flex-1 py-1 px-2 rounded-full bg-error text-white shadow-sm flex items-center justify-center gap-1";
  }

  // Animated Gauge
  if (gaugeCircle) {
    const radius = 30;
    const circumference = 2 * Math.PI * radius; // 188.4
    const offset = circumference - (res.score / 100) * circumference;
    gaugeCircle.style.strokeDashoffset = offset;
    gaugeCircle.style.stroke = res.gaugeColor;
  }

  // Level Badge
  if (levelBadge) {
    levelBadge.className = `inline-flex items-center gap-1.5 px-3 py-1 rounded-full font-bold text-xs ${res.badgeClass}`;
    levelBadge.innerHTML = `<span class="material-symbols-outlined text-[15px]">gpp_bad</span><span>${res.level}</span>`;
  }

  // Recommended Action
  if (actionBanner) {
    if (res.level === "HIGH RISK") {
      actionBanner.className = "p-3.5 rounded-xl bg-error-container text-on-error-container font-semibold text-xs flex items-center gap-2";
      actionBanner.innerHTML = `<span class="material-symbols-outlined text-error">dangerous</span><span>DO NOT CLICK LINKS • DO NOT PAY • PRESERVE EVIDENCE</span>`;
    } else {
      actionBanner.className = "p-3.5 rounded-xl bg-amber-100 text-amber-900 font-semibold text-xs flex items-center gap-2";
      actionBanner.innerHTML = `<span class="material-symbols-outlined text-amber-600">info</span><span>VERIFY SOURCE INDEPENDENTLY BEFORE RESPONDING</span>`;
    }
  }

  // Indicators
  if (indicatorsContainer) {
    indicatorsContainer.innerHTML = "";
    if (res.indicators.length === 0) {
      indicatorsContainer.innerHTML = `<div class="text-xs text-on-surface-variant p-2">No active aggressive indicators detected.</div>`;
    } else {
      res.indicators.forEach((ind, i) => {
        const item = document.createElement("div");
        item.className = "flex items-start gap-3 p-3 rounded-lg bg-surface-container-low";
        item.innerHTML = `
          <span class="material-symbols-outlined text-error text-[20px] shrink-0 mt-0.5">warning</span>
          <div class="min-w-0 flex-1">
            <p class="font-semibold text-xs text-on-surface">${ind}</p>
            <p class="text-[11px] text-on-surface-variant mt-0.5 leading-snug">${res.reasons[i] || 'Observed malicious heuristic pattern.'}</p>
          </div>
        `;
        indicatorsContainer.appendChild(item);
      });
    }
  }

  // Escalation buttons
  const escalateBtn = document.getElementById("btn-escalate-incident");
  if (escalateBtn) {
    escalateBtn.onclick = () => {
      navigateTo("screen-incident");
    };
  }

  const evidenceBtn = document.getElementById("btn-escalate-evidence");
  if (evidenceBtn) {
    evidenceBtn.onclick = () => {
      navigateTo("screen-evidence");
    };
  }
}

/**
 * Incident Response Checklist & Emergency
 */
function initIncidentChecklist() {
  const checks = [
    { id: "check-sever-contact", key: "severContact" },
    { id: "check-freeze-bank", key: "freezeAccounts" },
    { id: "check-preserve-evidence", key: "preserveEvidence" },
    { id: "check-dial-1930", key: "reportHelpline1930" },
    { id: "check-file-portal", key: "fileCyberPortal" }
  ];

  checks.forEach(c => {
    const el = document.getElementById(c.id);
    if (el) {
      el.addEventListener("change", e => {
        if (appState.activeCase) {
          const checked = e.target.checked;
          CaseManager.updateChecklist(appState.activeCase.id, c.key, checked);
          if (!appState.activeCase.checklist) appState.activeCase.checklist = {};
          appState.activeCase.checklist[c.key] = checked;
          renderIncidentScreen();
        }
      });
    }
  });
}

function renderIncidentScreen() {
  const currentCase = appState.activeCase || CaseManager.getActiveCase();
  const caseIdBadge = document.getElementById("incident-case-id-badge");
  const caseTitle = document.getElementById("incident-case-title");
  const timelineList = document.getElementById("incident-timeline-list");

  if (caseIdBadge && currentCase) {
    caseIdBadge.textContent = `Case #${currentCase.id}`;
  }
  if (caseTitle && currentCase) {
    caseTitle.textContent = currentCase.title;
  }

  // Sync checkboxes
  if (currentCase && currentCase.checklist) {
    const setChecked = (id, val) => {
      const el = document.getElementById(id);
      if (el) {
        const checked = !!val;
        el.checked = checked;
        const row = el.closest("label");
        if (row) {
          row.classList.toggle("bg-secondary-fixed", checked);
          row.classList.toggle("bg-surface-container-low", !checked);
          const title = row.querySelector("p");
          if (title) title.classList.toggle("line-through", checked);
        }
      }
    };
    setChecked("check-sever-contact", currentCase.checklist.severContact);
    setChecked("check-freeze-bank", currentCase.checklist.freezeAccounts);
    setChecked("check-preserve-evidence", currentCase.checklist.preserveEvidence);
    setChecked("check-dial-1930", currentCase.checklist.reportHelpline1930);
    setChecked("check-file-portal", currentCase.checklist.fileCyberPortal);

    const checklistKeys = ["severContact", "freezeAccounts", "preserveEvidence", "reportHelpline1930", "fileCyberPortal"];
    const completedCount = checklistKeys.filter(key => !!currentCase.checklist[key]).length;
    const progress = document.getElementById("incident-checklist-progress");
    const completeButton = document.getElementById("btn-complete-response");
    if (progress) {
      progress.textContent = completedCount === checklistKeys.length
        ? "All steps completed"
        : `${completedCount} of ${checklistKeys.length} actions completed`;
    }
    if (completeButton) {
      completeButton.classList.toggle("hidden", completedCount !== checklistKeys.length);
      completeButton.onclick = () => {
        currentCase.status = "RESPONSE_COMPLETED";
        currentCase.updatedAt = new Date().toISOString();
        CaseManager.saveCases(CaseManager.getCases().map(c => c.id === currentCase.id ? currentCase : c));
        renderIncidentScreen();
      };
    }
  }

  // Render Timeline
  if (timelineList && currentCase && currentCase.timeline) {
    timelineList.innerHTML = "";
    currentCase.timeline.slice().reverse().forEach(t => {
      const row = document.createElement("div");
      row.className = "flex items-start gap-2.5 text-xs text-on-surface-variant";
      row.innerHTML = `
        <span class="w-1.5 h-1.5 rounded-full bg-secondary mt-1.5 shrink-0"></span>
        <span class="font-mono text-[10px] text-outline shrink-0">${new Date(t.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
        <span class="text-on-surface flex-1">${t.event}</span>
      `;
      timelineList.appendChild(row);
    });
  }
}

/**
 * Evidence Creator & Dossier Exports
 */
function initEvidenceActions() {
  // Download Plain Text Report
  const btnExportTxt = document.getElementById("btn-export-txt");
  if (btnExportTxt) {
    btnExportTxt.addEventListener("click", () => {
      const c = appState.activeCase || CaseManager.getActiveCase();
      const report = CaseManager.generateReportText(c);
      downloadFile(`${c.id}_POLICE_EVIDENCE_REPORT.txt`, report, "text/plain");
    });
  }

  // Export JSON Package
  const btnExportJson = document.getElementById("btn-export-json");
  if (btnExportJson) {
    btnExportJson.addEventListener("click", () => {
      const c = appState.activeCase || CaseManager.getActiveCase();
      const json = JSON.stringify(c, null, 2);
      downloadFile(`${c.id}_EVIDENCE_PACKAGE.json`, json, "application/json");
    });
  }

  // Print PDF
  const btnPrintPdf = document.getElementById("btn-export-pdf");
  if (btnPrintPdf) {
    btnPrintPdf.addEventListener("click", () => {
      window.print();
    });
  }

  // Copy 1930 Helpline Script
  const btnCopyScript = document.getElementById("btn-copy-script");
  if (btnCopyScript) {
    btnCopyScript.addEventListener("click", () => {
      const c = appState.activeCase || CaseManager.getActiveCase();
      const script = `HELPLINE 1930 BRIEFING:
"Hello Officer, I want to report an ongoing digital scam.
Case ID: ${c.id}
Incident Type: ${c.categories.join(', ')}
Original Message: ${c.originalContent || 'See saved proof'}"`;

      navigator.clipboard.writeText(script).then(() => {
        btnCopyScript.innerHTML = `<span class="material-symbols-outlined text-[18px]">check</span><span>Copied to Clipboard!</span>`;
        setTimeout(() => {
          btnCopyScript.innerHTML = `<span class="material-symbols-outlined text-[18px]">content_copy</span><span>Copy 1930 Helpline Script</span>`;
        }, 2000);
      });
    });
  }

  // Add evidence prompt
  const btnAddEvidence = document.getElementById("btn-add-evidence-custom");
  if (btnAddEvidence) {
    btnAddEvidence.addEventListener("click", () => addEvidenceFromPrompt("message"));
  }

  const textEntry = document.getElementById("evidence-text-entry");
  const textInput = document.getElementById("evidence-text-input");
  const textSave = document.getElementById("evidence-text-save");
  if (textSave && textInput) {
    textSave.addEventListener("click", async () => {
      if (textInput.value.trim()) {
        await addEvidenceItem(textInput.dataset.evidenceType || "message", textInput.value.trim());
        textInput.value = "";
        textEntry.classList.add("hidden");
      }
    });
  }

  const fileInput = document.getElementById("evidence-file-input");
  document.querySelectorAll("[data-evidence-type]").forEach(button => {
    button.addEventListener("click", () => {
      const type = button.getAttribute("data-evidence-type");
      if (["screenshot", "image", "pdf", "voice"].includes(type)) {
        if (fileInput) {
          fileInput.dataset.evidenceType = type;
          fileInput.accept = type === "voice" ? "audio/*" : type === "pdf" ? ".pdf,application/pdf" : "image/*";
          fileInput.click();
        }
      } else {
        addEvidenceFromPrompt(type);
      }
    });
  });

  if (fileInput) {
    fileInput.addEventListener("change", async () => {
      const file = fileInput.files && fileInput.files[0];
      if (!file) return;
      await addEvidenceItem(fileInput.dataset.evidenceType || "file", file.name, {
        fileName: file.name,
        mimeType: file.type,
        size: file.size
      });
      fileInput.value = "";
    });
  }

  const detailFields = {
    "incident-description": "description",
    "incident-date-time": "dateTime",
    "incident-transaction-id": "transactionId",
    "incident-phone": "phoneNumber",
    "incident-upi": "upiId",
    "incident-notes": "notes"
  };
  Object.entries(detailFields).forEach(([id, key]) => {
    const field = document.getElementById(id);
    if (field) {
      field.addEventListener("input", () => {
        const c = appState.activeCase || CaseManager.getActiveCase();
        c.incidentDetails = c.incidentDetails || {};
        c.incidentDetails[key] = field.value;
        CaseManager.saveCases(CaseManager.getCases().map(item => item.id === c.id ? c : item));
      });
    }
  });
  }

async function addEvidenceFromPrompt(type) {
  const labels = {
    message: "Paste or type a message",
    payment: "Enter payment details or transaction reference",
    url: "Enter the suspicious URL",
    note: "Enter a note to save"
  };
  const textEntry = document.getElementById("evidence-text-entry");
  const textInput = document.getElementById("evidence-text-input");
  if (textEntry && textInput) {
    textInput.dataset.evidenceType = type;
    textInput.placeholder = labels[type] || "Enter details to save";
    textEntry.classList.remove("hidden");
    textInput.focus();
  }
}

async function addEvidenceItem(type, content, metadata = {}) {
  const c = appState.activeCase || CaseManager.getActiveCase();
  await CaseManager.addEvidence(c.id, type, content, metadata);
  appState.activeCase = CaseManager.getCases().find(item => item.id === c.id) || c;
  renderEvidenceScreen();
}

function renderEvidenceScreen() {
  const currentCase = appState.activeCase || CaseManager.getActiveCase();
  const caseIdBadge = document.getElementById("evidence-case-id");
  const evidenceList = document.getElementById("evidence-items-list");

  if (caseIdBadge && currentCase) {
    caseIdBadge.textContent = `Report #${currentCase.id}`;
  }

  const details = currentCase.incidentDetails || {};
  const detailValues = {
    "incident-description": details.description || currentCase.description || "",
    "incident-date-time": details.dateTime || "",
    "incident-transaction-id": details.transactionId || "",
    "incident-phone": details.phoneNumber || "",
    "incident-upi": details.upiId || "",
    "incident-notes": details.notes || ""
  };
  Object.entries(detailValues).forEach(([id, value]) => {
    const field = document.getElementById(id);
    if (field && document.activeElement !== field) field.value = value;
  });

  if (evidenceList && currentCase) {
    evidenceList.innerHTML = "";
    if (currentCase.evidence.length === 0) {
      evidenceList.innerHTML = `<div class="text-xs text-on-surface-variant p-3 bg-surface-container rounded-lg">No evidence items attached yet. Run a scan in Scan Hub to automatically capture items.</div>`;
    } else {
      currentCase.evidence.forEach((ev, i) => {
        const card = document.createElement("div");
        card.className = "bg-surface-container-lowest rounded-xl p-3.5 shadow-sm border border-outline-variant/30 flex flex-col gap-2";
        const icon = ev.type === "voice" ? "mic" : ev.type === "pdf" ? "picture_as_pdf" : ev.type === "screenshot" ? "screenshot" : ev.type === "image" ? "image" : ev.type === "payment" ? "receipt_long" : ev.type === "url" ? "link" : "chat";
        const label = ev.type.charAt(0).toUpperCase() + ev.type.slice(1);
        card.innerHTML = `
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-secondary uppercase tracking-wider flex items-center gap-1.5"><span class="material-symbols-outlined text-[16px]">${icon}</span>${label}</span>
            <button type="button" data-remove-evidence="${ev.id}" class="text-[11px] font-semibold text-error">Remove</button>
          </div>
          <p class="text-xs font-medium text-on-surface bg-surface-container-low p-2.5 rounded-lg select-all">${ev.metadata?.fileName || ev.content}</p>
          <div class="flex items-center justify-between text-[10px] text-on-surface-variant pt-1 border-t border-outline-variant/20">
            <span>${ev.metadata?.fileName ? "File details" : "Saved proof"}</span>
            <span>${new Date(ev.timestamp).toLocaleString([], {dateStyle:'medium', timeStyle:'short'})}</span>
          </div>
        `;
        card.querySelector("[data-remove-evidence]").addEventListener("click", () => {
          const cases = CaseManager.getCases();
          const target = cases.find(item => item.id === currentCase.id);
          if (target) {
            target.evidence = target.evidence.filter(item => item.id !== ev.id);
            target.updatedAt = new Date().toISOString();
            CaseManager.saveCases(cases);
            appState.activeCase = target;
            renderEvidenceScreen();
          }
        });
        evidenceList.appendChild(card);
      });
    }
  }
}

window.renderEvidenceScreen = renderEvidenceScreen;

/**
 * Home Dashboard Renderer
 */
function renderHome() {
  const cases = CaseManager.getCases();
  const recentList = document.getElementById("home-recent-scans");
  if (!recentList) return;

  recentList.innerHTML = "";
  if (cases.length === 0) {
    recentList.innerHTML = `
      <div class="p-4 rounded-xl bg-surface-container-lowest text-center text-xs text-on-surface-variant">
        No recent incidents recorded. Tap <strong>Start Quick Scan</strong> to test content.
      </div>
    `;
    return;
  }

  cases.slice(0, 4).forEach(c => {
    const item = document.createElement("div");
    item.className = "p-3.5 rounded-xl bg-surface-container-lowest shadow-sm hover:bg-surface-container-low transition-colors cursor-pointer flex items-center justify-between";
    item.onclick = () => {
      appState.activeCase = c;
      navigateTo("screen-incident");
    };

    const isHigh = c.riskLevel.includes("HIGH") || c.riskLevel.includes("CRITICAL");
    const dotColor = isHigh ? "bg-error" : "bg-warning-orange";

    item.innerHTML = `
      <div class="flex items-center gap-3 min-w-0">
        <div class="w-2.5 h-2.5 rounded-full ${dotColor} shrink-0"></div>
        <div class="min-w-0">
          <p class="text-xs font-semibold text-on-surface truncate">${c.title}</p>
          <p class="text-[11px] text-on-surface-variant truncate">${new Date(c.createdAt).toLocaleDateString()} • ${c.riskLevel}</p>
        </div>
      </div>
      <span class="material-symbols-outlined text-outline text-[18px]">chevron_right</span>
    `;
    recentList.appendChild(item);
  });
}

/**
 * File Downloader Helper
 */
function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  if (window.AndroidFileSaver && typeof FileReader !== "undefined") {
    const reader = new FileReader();
    reader.onloadend = () => {
      const dataUrl = reader.result;
      const base64 = typeof dataUrl === "string" ? dataUrl.substring(dataUrl.indexOf(",") + 1) : "";
      const saved = base64 && window.AndroidFileSaver.saveFile(filename, mimeType, base64);
      if (saved === false) alert("Could not save the report. Please try again.");
    };
    reader.readAsDataURL(blob);
    return;
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
