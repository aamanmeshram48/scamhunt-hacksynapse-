"""
ScamHunt — AI-assisted Cybersecurity Suite
============================================
Local-first desktop app (Tkinter) that helps a user detect, understand,
respond to, document, and report suspicious digital incidents.

Run:  python app.py
See README.md for setup / dependency notes and an architecture overview.
"""

import os
import shutil
import tempfile
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk

import engine
import file_tools
import ocr_tools
import qr_tools
import email_tools
import evidence_export
from case_manager import Case, STATUSES

# ============================================================
# COLORS
# ============================================================

BLACK = "#05050B"
DARK = "#080812"
SIDEBAR = "#090916"
PANEL = "#101020"
PANEL2 = "#15152A"

PURPLE = "#9B5CFF"
PURPLE_BRIGHT = "#B875FF"
BLUE = "#287BFF"
BLUE_BRIGHT = "#4DA3FF"

WHITE = "#F4F2FF"
GRAY = "#8888A8"

RED = "#FF3864"
ORANGE = "#FF9F43"
YELLOW = "#FFD166"
GREEN = "#35F5A0"

BORDER = "#252044"

APP_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(APP_DIR, "data", "uploads")
EXPORTS_DIR = os.path.join(APP_DIR, "data", "exports")
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(EXPORTS_DIR, exist_ok=True)


def color_for_level(level):
    return {
        "LOW RISK": GREEN,
        "SUSPICIOUS": ORANGE,
        "HIGH RISK": RED,
        "CRITICAL": RED,
    }.get(level, GRAY)


def store_uploaded_file(src_path):
    """Copy an uploaded file into our managed uploads dir so original
    evidence is preserved even if the user later moves/deletes the source."""
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d%H%M%S%f")
    fname = f"{ts}_{os.path.basename(src_path)}"
    dst = os.path.join(UPLOADS_DIR, fname)
    shutil.copy2(src_path, dst)
    return dst


# ============================================================
# REUSABLE WIDGETS
# ============================================================

class Section(tk.Frame):
    """A bordered card-style container with a title."""
    def __init__(self, parent, title=None, **kw):
        super().__init__(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, **kw)
        if title:
            tk.Label(self, text=title, font=("Consolas", 10, "bold"), fg=BLUE_BRIGHT, bg=PANEL)\
                .pack(anchor="w", padx=16, pady=(12, 6))


def styled_button(parent, text, command, bg=PURPLE, fg=WHITE, small=False):
    return tk.Button(
        parent, text=text, command=command,
        font=("Consolas", 8 if small else 9, "bold"),
        bg=bg, fg=fg, activebackground=PURPLE_BRIGHT, activeforeground=WHITE,
        relief="flat", cursor="hand2", padx=14, pady=8 if not small else 4,
    )


def labeled_entry(parent, label_text):
    tk.Label(parent, text=label_text, font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
        .pack(anchor="w", padx=16, pady=(6, 2))
    entry = tk.Entry(parent, font=("Consolas", 10), bg=PANEL2, fg=WHITE,
                      insertbackground=WHITE, relief="flat")
    entry.pack(fill="x", padx=16, ipady=6)
    return entry


def labeled_textbox(parent, label_text, height=6):
    tk.Label(parent, text=label_text, font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
        .pack(anchor="w", padx=16, pady=(6, 2))
    box = tk.Text(parent, font=("Consolas", 10), bg=PANEL2, fg=WHITE,
                   insertbackground=WHITE, relief="flat", height=height, wrap="word")
    box.pack(fill="x", padx=16, pady=(0, 6))
    return box


def warn_before_opening_link(url):
    proceed = messagebox.askyesno(
        "⚠ Suspicious Link Warning",
        "This link has been flagged as potentially suspicious.\n\n"
        f"{url}\n\n"
        "Opening it may expose you to phishing, malware, or fraud.\n\n"
        "Open anyway?",
        icon="warning",
    )
    if proceed:
        webbrowser.open(url)


# ============================================================
# RESULT RENDERER (shared across analyzers)
# ============================================================

def render_result(parent, result, urls=None, kind="text"):
    """Clears parent and draws a standard risk/analysis result block."""
    for w in parent.winfo_children():
        w.destroy()

    level = result.get("level", "LOW RISK")
    score = result.get("score", 0)
    color = color_for_level(level)

    header = tk.Frame(parent, bg=PANEL)
    header.pack(fill="x", padx=16, pady=(14, 6))

    tk.Label(header, text=level, font=("Consolas", 16, "bold"), fg=color, bg=PANEL).pack(side="left")
    tk.Label(header, text=f"  ({score}/100)", font=("Consolas", 11), fg=GRAY, bg=PANEL).pack(side="left")

    cats = result.get("categories", [])
    if cats:
        tk.Label(parent, text="CATEGORY: " + ", ".join(cats), font=("Consolas", 9, "bold"),
                  fg=BLUE_BRIGHT, bg=PANEL, wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(0, 8))

    inds = result.get("indicators", [])
    if inds:
        tk.Label(parent, text="INDICATORS DETECTED", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(4, 2))
        tk.Label(parent, text=" • ".join(inds), font=("Consolas", 9), fg=WHITE, bg=PANEL,
                  wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(0, 8))

    reasons = result.get("reasons", [])
    if reasons:
        tk.Label(parent, text="WHY?", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(4, 2))
        for r in reasons:
            tk.Label(parent, text="— " + r, font=("Consolas", 9), fg=WHITE, bg=PANEL,
                      wraplength=520, justify="left").pack(anchor="w", padx=16, pady=1)

    action = result.get("action")
    if action:
        tk.Label(parent, text="WHAT SHOULD I DO?", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(10, 2))
        tk.Label(parent, text=action, font=("Consolas", 9, "bold"), fg=color, bg=PANEL,
                  wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(0, 8))

    note = result.get("confidence_note")
    if note:
        tk.Label(parent, text=note, font=("Consolas", 8), fg=GRAY, bg=PANEL,
                  wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(4, 10))

    found_urls = urls if urls is not None else result.get("urls", [])
    if found_urls:
        tk.Label(parent, text="LINKS FOUND", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(6, 2))
        for u in found_urls[:8]:
            row = tk.Frame(parent, bg=PANEL)
            row.pack(fill="x", padx=16, pady=1)
            tk.Label(row, text=u, font=("Consolas", 8), fg=BLUE_BRIGHT, bg=PANEL,
                      wraplength=380, justify="left").pack(side="left")
            styled_button(row, "Open Link", lambda url=u: warn_before_opening_link(url), small=True, bg=PANEL2)\
                .pack(side="right")

    tk.Frame(parent, bg=PANEL, height=10).pack()


# ============================================================
# MAIN APP
# ============================================================

class ScamHunt:

    def __init__(self, root):
        self.root = root
        self.root.title("SCAMHUNT // CYBER SECURITY SUITE")
        self.root.geometry("1400x850")
        self.root.minsize(1100, 700)
        self.root.configure(bg=BLACK)

        self.pages = {}
        self.current_case = None  # active Case object for Incident Response

        self.build()

    # ------------------------------------------------------
    def build(self):
        self.create_sidebar()
        self.create_content()
        self.create_pages()
        self.show_page("Dashboard")

    # ------------------------------------------------------
    def create_sidebar(self):
        self.sidebar = tk.Frame(self.root, bg=SIDEBAR, width=245)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="◈", font=("Consolas", 38, "bold"), fg=PURPLE_BRIGHT, bg=SIDEBAR)\
            .pack(pady=(25, 0))
        tk.Label(self.sidebar, text="SCAMHUNT", font=("Consolas", 19, "bold"), fg=WHITE, bg=SIDEBAR).pack()
        tk.Label(self.sidebar, text="CYBER SECURITY SUITE", font=("Consolas", 7, "bold"),
                  fg=BLUE_BRIGHT, bg=SIDEBAR).pack(pady=(0, 20))

        self.nav_buttons = {}
        navigation = [
            ("⌂", "Dashboard"),
            ("◈", "AI Scam Detector"),
            ("▣", "File Analyzer"),
            ("◎", "Identity Impersonation"),
            ("✉", "Email Analyzer"),
            ("▦", "QR Analyzer"),
            ("⚠", "Cyber Abuse"),
            ("◉", "Surveillance / Espionage"),
            ("⚡", "Incident Response"),
            ("▤", "Evidence Creator"),
        ]

        canvas = tk.Canvas(self.sidebar, bg=SIDEBAR, highlightthickness=0)
        canvas.pack(side="top", fill="both", expand=True)
        nav_frame = tk.Frame(canvas, bg=SIDEBAR)
        canvas.create_window((0, 0), window=nav_frame, anchor="nw", width=245)
        nav_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        for icon, name in navigation:
            button = tk.Button(
                nav_frame, text=f"{icon}   {name}", command=lambda n=name: self.show_page(n),
                font=("Consolas", 9, "bold"), anchor="w", bg=SIDEBAR, fg=GRAY,
                activebackground="#20183D", activeforeground=WHITE, relief="flat",
                cursor="hand2", padx=20, pady=12,
            )
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[name] = button

        bottom = tk.Frame(self.sidebar, bg=SIDEBAR)
        bottom.pack(side="bottom", fill="x", padx=15, pady=20)
        tk.Label(bottom, text="● SYSTEM ONLINE", font=("Consolas", 8, "bold"), fg=GREEN, bg=SIDEBAR)\
            .pack(anchor="w")
        tk.Label(bottom, text="LOCAL ANALYSIS ENGINE", font=("Consolas", 7), fg=GRAY, bg=SIDEBAR)\
            .pack(anchor="w", pady=(4, 0))

    # ------------------------------------------------------
    def create_content(self):
        self.content = tk.Frame(self.root, bg=BLACK)
        self.content.pack(side="right", fill="both", expand=True)

    def create_pages(self):
        self.create_dashboard()
        self.create_scam_detector_page()
        self.create_file_analyzer_page()
        self.create_identity_page()
        self.create_email_page()
        self.create_qr_page()
        self.create_abuse_page()
        self.create_surveillance_page()
        self.create_incident_page()
        self.create_evidence_creator_page()

    def new_page(self, name):
        page = tk.Frame(self.content, bg=BLACK)
        self.pages[name] = page
        return page

    def page_title(self, parent, title, subtitle):
        tk.Label(parent, text=title, font=("Consolas", 25, "bold"), fg=WHITE, bg=BLACK)\
            .pack(anchor="w", padx=35, pady=(30, 2))
        tk.Label(parent, text=subtitle, font=("Consolas", 9), fg=GRAY, bg=BLACK)\
            .pack(anchor="w", padx=35, pady=(0, 25))

    def show_page(self, name):
        for n, btn in self.nav_buttons.items():
            btn.configure(bg=SIDEBAR, fg=GRAY)
        if name in self.nav_buttons:
            self.nav_buttons[name].configure(bg="#20183D", fg=WHITE)
        for p in self.pages.values():
            p.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        self.current_page = name

    def two_column(self, page):
        wrap = tk.Frame(page, bg=BLACK)
        wrap.pack(fill="both", expand=True, padx=35, pady=(0, 25))
        left = tk.Frame(wrap, bg=BLACK)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        right_outer = tk.Frame(wrap, bg=BLACK, width=560)
        right_outer.pack(side="left", fill="both")
        right_outer.pack_propagate(False)
        right_canvas = tk.Canvas(right_outer, bg=BLACK, highlightthickness=0)
        right_scroll = tk.Scrollbar(right_outer, orient="vertical", command=right_canvas.yview)
        right = Section(right_canvas, title="ANALYSIS RESULT")
        right_canvas.create_window((0, 0), window=right, anchor="nw", width=540)
        right.bind("<Configure>", lambda e: right_canvas.configure(scrollregion=right_canvas.bbox("all")))
        right_canvas.configure(yscrollcommand=right_scroll.set)
        right_canvas.pack(side="left", fill="both", expand=True)
        right_scroll.pack(side="right", fill="y")
        return left, right

    # ========================================================
    # DASHBOARD
    # ========================================================

    def create_dashboard(self):
        page = self.new_page("Dashboard")
        self.page_title(page, "COMMAND CENTER", "SCAMHUNT DIGITAL THREAT MONITORING")

        cards = tk.Frame(page, bg=BLACK)
        cards.pack(fill="x", padx=35)

        card_data = [
            ("AI SCAM DETECTION", "READY", PURPLE_BRIGHT),
            ("FILE ANALYZER", "READY", BLUE_BRIGHT),
            ("CYBER ABUSE", "READY", ORANGE),
            ("SURVEILLANCE", "READY", RED),
        ]
        for title, value, color in card_data:
            card = tk.Frame(cards, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=6)
            tk.Label(card, text=title, font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
                .pack(anchor="w", padx=18, pady=(18, 4))
            tk.Label(card, text=value, font=("Consolas", 19, "bold"), fg=color, bg=PANEL)\
                .pack(anchor="w", padx=18, pady=(0, 18))

        grid = tk.Frame(page, bg=BLACK)
        grid.pack(fill="both", expand=True, padx=35, pady=20)

        modules = [
            ("◈ AI Scam Detector", "Analyze text/messages for scam & social-engineering patterns.", "AI Scam Detector"),
            ("▣ File Analyzer", "Safely inspect suspicious files without executing them.", "File Analyzer"),
            ("◎ Identity Impersonation", "Check emails, websites & profiles for impersonation.", "Identity Impersonation"),
            ("✉ Email Analyzer", "Deep-dive phishing analysis of a specific email.", "Email Analyzer"),
            ("▦ QR / Payment QR Analyzer", "Decode QR codes and check payment QR safety.", "QR Analyzer"),
            ("⚠ Cyber Abuse Assistance", "Calm, practical help for harassment, threats & extortion.", "Cyber Abuse"),
            ("◉ Surveillance / Espionage", "Spot signs of stalkerware, spyware & monitoring.", "Surveillance / Espionage"),
            ("⚡ Incident Response", "Open a case, collect evidence, get an AI case assistant.", "Incident Response"),
            ("▤ Evidence Creator", "Export a structured, shareable evidence package.", "Evidence Creator"),
        ]

        for i, (title, desc, target) in enumerate(modules):
            r, c = divmod(i, 3)
            tile = tk.Frame(grid, bg=PANEL, highlightbackground=BORDER, highlightthickness=1, cursor="hand2")
            tile.grid(row=r, column=c, sticky="nsew", padx=8, pady=8)
            grid.grid_columnconfigure(c, weight=1)
            tk.Label(tile, text=title, font=("Consolas", 11, "bold"), fg=WHITE, bg=PANEL)\
                .pack(anchor="w", padx=16, pady=(16, 6))
            tk.Label(tile, text=desc, font=("Consolas", 8), fg=GRAY, bg=PANEL, wraplength=280, justify="left")\
                .pack(anchor="w", padx=16, pady=(0, 12))
            btn = styled_button(tile, "Open →", lambda t=target: self.show_page(t), bg=PANEL2)
            btn.pack(anchor="w", padx=16, pady=(0, 16))

        journey = tk.Label(
            page, text="Detect → Understand → Assess Risk → Take Action → Preserve Evidence → Respond → Report",
            font=("Consolas", 8, "bold"), fg=BLUE_BRIGHT, bg=BLACK,
        )
        journey.pack(anchor="w", padx=35, pady=(0, 20))

    # ========================================================
    # AI SCAM DETECTOR
    # ========================================================

    def create_scam_detector_page(self):
        page = self.new_page("AI Scam Detector")
        self.page_title(page, "AI SCAM DETECTOR", "PASTE A MESSAGE OR ATTACH A SCREENSHOT FOR ANALYSIS")
        left, right = self.two_column(page)

        demo_section = Section(left, title="QUICK DEMO SAMPLES")
        demo_section.pack(fill="x", pady=(0, 10))
        demo_row = tk.Frame(demo_section, bg=PANEL)
        demo_row.pack(fill="x", padx=16, pady=(0, 14))
        for name in list(engine.DEMO_MESSAGES.keys())[:4]:
            styled_button(demo_row, name, lambda n=name: self._load_demo(text_box, n), small=True, bg=PANEL2)\
                .pack(side="left", padx=(0, 6), pady=4)

        input_section = Section(left, title="MESSAGE / TEXT INPUT")
        input_section.pack(fill="both", expand=True)
        text_box = labeled_textbox(input_section, "Paste SMS / WhatsApp / social message / email body", height=14)

        attach_row = tk.Frame(input_section, bg=PANEL)
        attach_row.pack(fill="x", padx=16, pady=(0, 6))
        self.scam_attachment_path = tk.StringVar(value="")
        tk.Label(attach_row, textvariable=self.scam_attachment_path, font=("Consolas", 8), fg=GRAY, bg=PANEL)\
            .pack(side="left")
        styled_button(attach_row, "Attach Screenshot", lambda: self._attach_scam_image(), small=True, bg=PANEL2)\
            .pack(side="right")

        btn_row = tk.Frame(input_section, bg=PANEL)
        btn_row.pack(fill="x", padx=16, pady=(6, 16))
        styled_button(btn_row, "Analyze", lambda: self._run_scam_detector(text_box, right)).pack(side="left")
        styled_button(btn_row, "Clear", lambda: self._clear_scam(text_box), bg=PANEL2).pack(side="left", padx=8)

        self.scam_text_box_ref = text_box

    def _load_demo(self, text_box, name):
        text_box.delete("1.0", "end")
        text_box.insert("1.0", engine.DEMO_MESSAGES[name])

    def _attach_scam_image(self):
        path = filedialog.askopenfilename(
            title="Attach screenshot",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All files", "*.*")],
        )
        if path:
            self.scam_attachment_path.set(f"Attached: {os.path.basename(path)}")
            self._scam_attachment_full_path = path

    def _clear_scam(self, text_box):
        text_box.delete("1.0", "end")
        self.scam_attachment_path.set("")
        self._scam_attachment_full_path = None

    def _run_scam_detector(self, text_box, right_panel):
        text = text_box.get("1.0", "end").strip()
        attachment = getattr(self, "_scam_attachment_full_path", None)
        extra_text = ""

        if attachment:
            shot = ocr_tools.analyze_screenshot(attachment)
            if shot["ocr_error"] and not shot["ocr_text"]:
                messagebox.showwarning("OCR", shot["ocr_error"])
            extra_text = shot["ocr_text"]
            if shot["qr_payloads"]:
                extra_text += "\n" + "\n".join(shot["qr_payloads"])

        combined = (text + "\n" + extra_text).strip()
        if not combined:
            messagebox.showinfo("AI Scam Detector", "Please paste a message or attach a screenshot first.")
            return

        result = engine.analyze(combined)
        render_result(right_panel, result)
        self._last_scam_result = result
        self._last_scam_text = combined

    # ========================================================
    # FILE ANALYZER
    # ========================================================

    def create_file_analyzer_page(self):
        page = self.new_page("File Analyzer")
        self.page_title(page, "FILE ANALYZER", "SAFE, STATIC ANALYSIS — FILES ARE NEVER EXECUTED")
        left, right = self.two_column(page)

        section = Section(left, title="UPLOAD A SUSPICIOUS FILE")
        section.pack(fill="x")
        self.file_path_var = tk.StringVar(value="No file selected.")
        tk.Label(section, textvariable=self.file_path_var, font=("Consolas", 9), fg=WHITE, bg=PANEL,
                  wraplength=500, justify="left").pack(anchor="w", padx=16, pady=(0, 10))
        btn_row = tk.Frame(section, bg=PANEL)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        styled_button(btn_row, "Choose File", lambda: self._choose_file()).pack(side="left")
        styled_button(btn_row, "Analyze File", lambda: self._run_file_analysis(right), bg=PANEL2).pack(side="left", padx=8)

        info = Section(left, title="WHAT WE CHECK")
        info.pack(fill="x", pady=(12, 0))
        tk.Label(info, text=(
            "• File type vs. extension mismatch\n"
            "• Executable / script file types\n"
            "• Macro-enabled Office documents\n"
            "• Double-extension disguise tricks\n"
            "• SHA-256 hash for integrity/reporting\n"
            "• Embedded URLs inside the file\n\n"
            "This does NOT run a live antivirus/malware-signature scan.\n"
            "Treat results as an initial screening."
        ), font=("Consolas", 9), fg=GRAY, bg=PANEL, justify="left").pack(anchor="w", padx=16, pady=(0, 16))

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Choose a file to analyze")
        if path:
            self._file_analyzer_path = path
            self.file_path_var.set(f"Selected: {path}")

    def _run_file_analysis(self, right_panel):
        path = getattr(self, "_file_analyzer_path", None)
        if not path or not os.path.exists(path):
            messagebox.showinfo("File Analyzer", "Please choose a file first.")
            return
        try:
            size = os.path.getsize(path)
        except OSError as e:
            messagebox.showerror("File Analyzer", f"Could not read file: {e}")
            return
        if size > file_tools.MAX_SAFE_SIZE:
            if not messagebox.askyesno(
                "Large file",
                f"This file is larger than {file_tools.MAX_SAFE_SIZE // (1024*1024)} MB. "
                "Only a partial header check will be performed. Continue?"
            ):
                return

        result = file_tools.analyze_file(path)
        if result.get("error"):
            messagebox.showwarning("File Analyzer", result["error"])

        for w in right_panel.winfo_children():
            w.destroy()
        level = result["level"]
        color = color_for_level(level)
        tk.Label(right_panel, text=level, font=("Consolas", 16, "bold"), fg=color, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(14, 6))
        rows = [
            ("File name", result["filename"]),
            ("File size", f"{result['size']} bytes" if result["size"] is not None else "?"),
            ("Declared extension", result["declared_ext"]),
            ("MIME guess", result["mime_guess"]),
            ("Detected type (magic bytes)", result["detected_type"]),
            ("Extension mismatch", "YES ⚠" if result["extension_mismatch"] else "No"),
            ("SHA-256", result["sha256"] or "(not computed)"),
        ]
        for label, val in rows:
            tk.Label(right_panel, text=f"{label}: {val}", font=("Consolas", 9), fg=WHITE, bg=PANEL,
                      wraplength=520, justify="left").pack(anchor="w", padx=16, pady=1)

        if result["indicators"]:
            tk.Label(right_panel, text="INDICATORS", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
                .pack(anchor="w", padx=16, pady=(10, 2))
            tk.Label(right_panel, text=" • ".join(result["indicators"]), font=("Consolas", 9), fg=WHITE,
                      bg=PANEL, wraplength=520, justify="left").pack(anchor="w", padx=16)

        for r in result["reasons"]:
            tk.Label(right_panel, text="— " + r, font=("Consolas", 9), fg=WHITE, bg=PANEL,
                      wraplength=520, justify="left").pack(anchor="w", padx=16, pady=1)

        if result["urls_found"]:
            tk.Label(right_panel, text="EMBEDDED URLS", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
                .pack(anchor="w", padx=16, pady=(10, 2))
            for u in result["urls_found"][:8]:
                tk.Label(right_panel, text=u, font=("Consolas", 8), fg=BLUE_BRIGHT, bg=PANEL,
                          wraplength=520, justify="left").pack(anchor="w", padx=16, pady=1)

        tk.Label(right_panel, text="RECOMMENDED ACTION", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(10, 2))
        tk.Label(right_panel, text=result["action"], font=("Consolas", 9, "bold"), fg=color, bg=PANEL,
                  wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(0, 8))
        tk.Label(right_panel, text=result["confidence_note"], font=("Consolas", 8), fg=GRAY, bg=PANEL,
                  wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(4, 14))

        self._last_file_result = result
        self._last_file_path = path

    # ========================================================
    # IDENTITY IMPERSONATION
    # ========================================================

    def create_identity_page(self):
        page = self.new_page("Identity Impersonation")
        self.page_title(page, "IDENTITY IMPERSONATION DETECTOR", "CHECK EMAILS, WEBSITES, AND SOCIAL PROFILES")
        left, right = self.two_column(page)

        url_section = Section(left, title="WEBSITE / URL")
        url_section.pack(fill="x")
        url_entry = labeled_entry(url_section, "Enter a website URL to check")
        styled_button(url_section, "Check Website", lambda: self._check_identity_url(url_entry, right))\
            .pack(anchor="w", padx=16, pady=(8, 16))

        email_section = Section(left, title="SENDER EMAIL ADDRESS")
        email_section.pack(fill="x", pady=(12, 0))
        email_entry = labeled_entry(email_section, "e.g. \"Bank Support\" <random123@gmail.com>")
        styled_button(email_section, "Check Sender", lambda: self._check_identity_email(email_entry, right))\
            .pack(anchor="w", padx=16, pady=(8, 16))

        profile_section = Section(left, title="SOCIAL MEDIA PROFILE / COMPANY CLAIM")
        profile_section.pack(fill="both", expand=True, pady=(12, 0))
        profile_box = labeled_textbox(profile_section, "Paste profile bio, company claim, or suspicious message", height=8)
        styled_button(profile_section, "Check Profile Text", lambda: self._check_identity_text(profile_box, right))\
            .pack(anchor="w", padx=16, pady=(0, 16))

    def _check_identity_url(self, entry, right):
        url = entry.get().strip()
        if not url:
            messagebox.showinfo("Identity Impersonation", "Enter a URL first.")
            return
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url
        score, indicators, categories, reasons = engine.analyze_url_indicators(url)
        level, color = engine.risk_level_from_score(score)
        result = {
            "score": score, "level": level, "color": color,
            "categories": categories or ["NO CLEAR IMPERSONATION SIGNAL"],
            "indicators": indicators, "reasons": reasons or ["No strong impersonation indicators found in the URL structure itself."],
            "action": engine.recommended_action(level),
            "confidence_note": "This checks URL/domain structure only — wording such as \"Potential impersonation detected\" reflects "
                                "pattern-based analysis, not a confirmed determination.",
        }
        render_result(right, result, urls=[url])

    def _check_identity_email(self, entry, right):
        sender = entry.get().strip()
        if not sender:
            messagebox.showinfo("Identity Impersonation", "Enter a sender address first.")
            return
        result = email_tools.analyze_email(sender=sender, subject="", body="")
        result["confidence_note"] = "Sender-only check: wording such as \"Potential impersonation detected\" reflects pattern " \
                                     "analysis, not a confirmed determination."
        render_result(right, result)

    def _check_identity_text(self, box, right):
        text = box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("Identity Impersonation", "Paste some profile/company text first.")
            return
        result = engine.analyze(text)
        result["confidence_note"] = "Wording such as \"Potential impersonation detected\" reflects pattern analysis of the " \
                                     "text provided, not a confirmed determination."
        render_result(right, result)

    # ========================================================
    # EMAIL ANALYZER
    # ========================================================

    def create_email_page(self):
        page = self.new_page("Email Analyzer")
        self.page_title(page, "EMAIL ANALYZER", "PASTE A RAW EMAIL, OR FILL IN THE FIELDS BELOW")
        left, right = self.two_column(page)

        raw_section = Section(left, title="PASTE RAW EMAIL (.eml text) — OPTIONAL")
        raw_section.pack(fill="x")
        raw_box = labeled_textbox(raw_section, "Paste full raw email source here (headers + body)", height=6)
        tk.Frame(raw_section, bg=PANEL, height=6).pack()

        fields_section = Section(left, title="OR FILL IN FIELDS MANUALLY")
        fields_section.pack(fill="both", expand=True, pady=(12, 0))
        sender_entry = labeled_entry(fields_section, "Sender (e.g. \"Bank\" <name@domain.com>)")
        subject_entry = labeled_entry(fields_section, "Subject")
        body_box = labeled_textbox(fields_section, "Email body", height=10)

        styled_button(fields_section, "Analyze Email",
                       lambda: self._run_email_analysis(raw_box, sender_entry, subject_entry, body_box, right))\
            .pack(anchor="w", padx=16, pady=(6, 16))

    def _run_email_analysis(self, raw_box, sender_entry, subject_entry, body_box, right):
        raw = raw_box.get("1.0", "end").strip()
        sender = sender_entry.get().strip()
        subject = subject_entry.get().strip()
        body = body_box.get("1.0", "end").strip()

        if not raw and not (sender or subject or body):
            messagebox.showinfo("Email Analyzer", "Paste a raw email or fill in at least one field.")
            return

        result = email_tools.analyze_email(sender=sender, subject=subject, body=body, raw_eml=raw)

        for w in right.winfo_children():
            w.destroy()
        level, color = result["level"], color_for_level(result["level"])
        tk.Label(right, text=level, font=("Consolas", 16, "bold"), fg=color, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(14, 6))
        tk.Label(right, text=f"({result['score']}/100)", font=("Consolas", 10), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16)
        tk.Label(right, text=f"Sender address: {result['sender_address'] or '(none provided)'}",
                  font=("Consolas", 9), fg=WHITE, bg=PANEL, wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(8, 1))
        tk.Label(right, text=f"Sender domain: {result['sender_domain'] or '(none)'}",
                  font=("Consolas", 9), fg=WHITE, bg=PANEL).pack(anchor="w", padx=16, pady=1)
        tk.Label(right, text="CATEGORY: " + ", ".join(result["categories"]), font=("Consolas", 9, "bold"),
                  fg=BLUE_BRIGHT, bg=PANEL, wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(8, 8))

        if result["indicators"]:
            tk.Label(right, text="INDICATORS", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
                .pack(anchor="w", padx=16, pady=(2, 2))
            tk.Label(right, text=" • ".join(result["indicators"]), font=("Consolas", 9), fg=WHITE, bg=PANEL,
                      wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(0, 8))

        for r in result["reasons"]:
            tk.Label(right, text="— " + r, font=("Consolas", 9), fg=WHITE, bg=PANEL,
                      wraplength=520, justify="left").pack(anchor="w", padx=16, pady=1)

        tk.Label(right, text="WHAT SHOULD I DO?", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(10, 2))
        tk.Label(right, text=result["action"], font=("Consolas", 9, "bold"), fg=color, bg=PANEL,
                  wraplength=520, justify="left").pack(anchor="w", padx=16, pady=(0, 10))

        if result["urls"]:
            tk.Label(right, text="LINKS FOUND", font=("Consolas", 8, "bold"), fg=GRAY, bg=PANEL)\
                .pack(anchor="w", padx=16, pady=(2, 2))
            for u in result["urls"][:8]:
                row = tk.Frame(right, bg=PANEL)
                row.pack(fill="x", padx=16, pady=1)
                tk.Label(row, text=u, font=("Consolas", 8), fg=BLUE_BRIGHT, bg=PANEL,
                          wraplength=380, justify="left").pack(side="left")
                styled_button(row, "Open Link", lambda url=u: warn_before_opening_link(url), small=True, bg=PANEL2)\
                    .pack(side="right")
        tk.Frame(right, bg=PANEL, height=10).pack()
        self._last_email_result = result

    # ========================================================
    # QR ANALYZER (incl. Payment QR)
    # ========================================================

    def create_qr_page(self):
        page = self.new_page("QR Analyzer")
        self.page_title(page, "QR / PAYMENT QR ANALYZER", "DECODE A QR CODE IMAGE AND CHECK ITS SAFETY")
        left, right = self.two_column(page)

        section = Section(left, title="UPLOAD QR CODE IMAGE")
        section.pack(fill="x")
        self.qr_path_var = tk.StringVar(value="No image selected.")
        tk.Label(section, textvariable=self.qr_path_var, font=("Consolas", 9), fg=WHITE, bg=PANEL,
                  wraplength=500, justify="left").pack(anchor="w", padx=16, pady=(0, 10))
        btn_row = tk.Frame(section, bg=PANEL)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        styled_button(btn_row, "Choose QR Image", lambda: self._choose_qr_image()).pack(side="left")
        styled_button(btn_row, "Decode & Analyze", lambda: self._run_qr_analysis(right), bg=PANEL2).pack(side="left", padx=8)

        if not qr_tools.QR_AVAILABLE:
            tk.Label(section, text="⚠ QR decoding library (pyzbar) is not installed — see requirements.txt.",
                      font=("Consolas", 8), fg=ORANGE, bg=PANEL, wraplength=500, justify="left")\
                .pack(anchor="w", padx=16, pady=(0, 12))

        info = Section(left, title="PAYMENT QR SAFETY")
        info.pack(fill="x", pady=(12, 0))
        tk.Label(info, text=(
            "ScamHunt never makes a payment for you. For payment (UPI-style) QR codes, "
            "it only decodes and shows the payee ID, amount, and note so you can verify "
            "the recipient and purpose before paying manually in your own payment app."
        ), font=("Consolas", 9), fg=GRAY, bg=PANEL, wraplength=500, justify="left").pack(anchor="w", padx=16, pady=(0, 16))

    def _choose_qr_image(self):
        path = filedialog.askopenfilename(
            title="Choose QR code image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All files", "*.*")],
        )
        if path:
            self._qr_image_path = path
            self.qr_path_var.set(f"Selected: {path}")

    def _run_qr_analysis(self, right):
        path = getattr(self, "_qr_image_path", None)
        if not path:
            messagebox.showinfo("QR Analyzer", "Choose a QR code image first.")
            return
        if not qr_tools.QR_AVAILABLE:
            messagebox.showwarning("QR Analyzer", "QR decoding is unavailable (pyzbar not installed).")
            return

        payloads = qr_tools.decode_qr_image(path)
        if not payloads:
            messagebox.showinfo("QR Analyzer", "No QR code could be decoded from this image.")
            return

        for w in right.winfo_children():
            w.destroy()

        self._last_qr_results = []
        for i, payload in enumerate(payloads):
            info = qr_tools.analyze_qr_payload(payload)
            self._last_qr_results.append(info)
            color = color_for_level(info["level"])
            box = Section(right, title=f"QR PAYLOAD #{i+1} — {info['type'].upper()}")
            box.pack(fill="x", padx=16, pady=8)
            tk.Label(box, text=info["level"], font=("Consolas", 13, "bold"), fg=color, bg=PANEL)\
                .pack(anchor="w", padx=16, pady=(0, 4))
            tk.Label(box, text=f"Raw content: {info['raw']}", font=("Consolas", 8), fg=GRAY, bg=PANEL,
                      wraplength=480, justify="left").pack(anchor="w", padx=16, pady=(0, 6))

            if info["upi"]:
                for k, v in info["upi"].items():
                    if v:
                        tk.Label(box, text=f"{k.replace('_',' ').title()}: {v}", font=("Consolas", 9), fg=WHITE, bg=PANEL)\
                            .pack(anchor="w", padx=16, pady=1)
                tk.Label(box, text="⚠ Verify the payee and amount in your own UPI app before paying. "
                                    "ScamHunt will not initiate any payment.",
                          font=("Consolas", 8, "bold"), fg=ORANGE, bg=PANEL, wraplength=480, justify="left")\
                    .pack(anchor="w", padx=16, pady=(6, 6))

            if info["indicators"]:
                tk.Label(box, text=" • ".join(info["indicators"]), font=("Consolas", 9), fg=WHITE, bg=PANEL,
                          wraplength=480, justify="left").pack(anchor="w", padx=16, pady=(0, 4))
            for r in info["reasons"]:
                tk.Label(box, text="— " + r, font=("Consolas", 9), fg=WHITE, bg=PANEL,
                          wraplength=480, justify="left").pack(anchor="w", padx=16, pady=1)

            if info["urls"]:
                for u in info["urls"]:
                    row = tk.Frame(box, bg=PANEL)
                    row.pack(fill="x", padx=16, pady=1)
                    tk.Label(row, text=u, font=("Consolas", 8), fg=BLUE_BRIGHT, bg=PANEL,
                              wraplength=340, justify="left").pack(side="left")
                    styled_button(row, "Open Link", lambda url=u: warn_before_opening_link(url), small=True, bg=PANEL2)\
                        .pack(side="right")

            tk.Label(box, text=info["action"], font=("Consolas", 9, "bold"), fg=color, bg=PANEL,
                      wraplength=480, justify="left").pack(anchor="w", padx=16, pady=(6, 12))

    # ========================================================
    # CYBER ABUSE ASSISTANCE
    # ========================================================

    def create_abuse_page(self):
        page = self.new_page("Cyber Abuse")
        self.page_title(page, "CYBER ABUSE ASSISTANCE", "CALM, PRACTICAL SUPPORT — DESCRIBE THE SITUATION")
        left, right = self.two_column(page)

        section = Section(left, title="DESCRIBE WHAT IS HAPPENING")
        section.pack(fill="both", expand=True)
        tk.Label(section, text=(
            "Paste messages you received, or describe the situation in your own words "
            "(harassment, bullying, threats, blackmail, stalking, impersonation, image-based abuse, etc.)"
        ), font=("Consolas", 8), fg=GRAY, bg=PANEL, wraplength=500, justify="left").pack(anchor="w", padx=16, pady=(0, 6))
        box = labeled_textbox(section, "Description / messages", height=16)
        styled_button(section, "Get Guidance", lambda: self._run_abuse_analysis(box, right))\
            .pack(anchor="w", padx=16, pady=(6, 16))

    def _run_abuse_analysis(self, box, right):
        text = box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("Cyber Abuse Assistance", "Please describe the situation first.")
            return
        result = engine.analyze(text)

        abuse_categories = {"CYBERSTALKING", "CYBERBULLYING", "ONLINE THREAT", "EXTORTION", "SUSPECTED SURVEILLANCE"}
        matched = [c for c in result["categories"] if c in abuse_categories]

        for w in right.winfo_children():
            w.destroy()
        color = color_for_level(result["level"])
        tk.Label(right, text=result["level"], font=("Consolas", 16, "bold"), fg=color, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(14, 6))

        tk.Label(right, text="WHAT MAY BE HAPPENING", font=("Consolas", 9, "bold"), fg=BLUE_BRIGHT, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(4, 2))
        what = ", ".join(matched) if matched else "No strong abuse-pattern signal detected in this text, but trust your own judgement about the situation."
        tk.Label(right, text=what, font=("Consolas", 9), fg=WHITE, bg=PANEL, wraplength=520, justify="left")\
            .pack(anchor="w", padx=16, pady=(0, 10))

        tk.Label(right, text="IMMEDIATE SAFETY STEPS", font=("Consolas", 9, "bold"), fg=BLUE_BRIGHT, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(4, 2))
        steps = (
            "• Block the sender/account where possible.\n"
            "• Avoid engaging further or responding to provocations.\n"
            "• Tell someone you trust what is happening.\n"
            "• If you feel physically unsafe, contact local emergency services."
        )
        tk.Label(right, text=steps, font=("Consolas", 9), fg=WHITE, bg=PANEL, wraplength=520, justify="left")\
            .pack(anchor="w", padx=16, pady=(0, 10))

        tk.Label(right, text="EVIDENCE YOU SHOULD PRESERVE", font=("Consolas", 9, "bold"), fg=BLUE_BRIGHT, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(4, 2))
        evid = (
            "• Full screenshots (with visible date/time and username)\n"
            "• URLs/profile links involved\n"
            "• Usernames and any known real names\n"
            "• Dates and times of each incident\n"
            "• The original messages themselves — do not delete them"
        )
        tk.Label(right, text=evid, font=("Consolas", 9), fg=WHITE, bg=PANEL, wraplength=520, justify="left")\
            .pack(anchor="w", padx=16, pady=(0, 10))

        tk.Label(right, text="WHAT NOT TO DO", font=("Consolas", 9, "bold"), fg=BLUE_BRIGHT, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(4, 2))
        avoid = (
            "• Do not send money or gift cards.\n"
            "• Do not share passwords, OTPs, or further personal photos.\n"
            "• Do not retaliate or escalate contact.\n"
            "• Do not delete the evidence, even if it's upsetting to keep."
        )
        tk.Label(right, text=avoid, font=("Consolas", 9), fg=WHITE, bg=PANEL, wraplength=520, justify="left")\
            .pack(anchor="w", padx=16, pady=(0, 10))

        tk.Label(right, text="REPORTING / HELP OPTIONS (INDIA)", font=("Consolas", 9, "bold"), fg=BLUE_BRIGHT, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(4, 2))
        report = (
            "• National Cyber Crime Reporting Portal: cybercrime.gov.in\n"
            "• Cyber Crime Helpline: 1930\n"
            "• Local police station (in-person complaint / FIR)\n"
            "• Platform's in-app report/block feature"
        )
        tk.Label(right, text=report, font=("Consolas", 9), fg=WHITE, bg=PANEL, wraplength=520, justify="left")\
            .pack(anchor="w", padx=16, pady=(0, 14))

        tk.Label(right, text="This guidance is general safety information, not legal advice.",
                  font=("Consolas", 8), fg=GRAY, bg=PANEL, wraplength=520, justify="left")\
            .pack(anchor="w", padx=16, pady=(0, 14))

        self._last_abuse_result = result

    # ========================================================
    # SURVEILLANCE / ESPIONAGE
    # ========================================================

    def create_surveillance_page(self):
        page = self.new_page("Surveillance / Espionage")
        self.page_title(page, "SURVEILLANCE / ESPIONAGE CHECK", "SIGNS OF STALKERWARE, SPYWARE, OR MONITORING")
        left, right = self.two_column(page)

        section = Section(left, title="DESCRIBE WHAT YOU'VE NOTICED")
        section.pack(fill="both", expand=True)
        tk.Label(section, text=(
            "Examples: unfamiliar apps on your device, someone always knowing your location, "
            "messages mentioning things only visible on your phone, unexpected remote-access requests."
        ), font=("Consolas", 8), fg=GRAY, bg=PANEL, wraplength=500, justify="left").pack(anchor="w", padx=16, pady=(0, 6))
        box = labeled_textbox(section, "Description", height=14)
        styled_button(section, "Analyze", lambda: self._run_surveillance_analysis(box, right))\
            .pack(anchor="w", padx=16, pady=(6, 16))

        checklist = Section(left, title="QUICK SELF-CHECK")
        checklist.pack(fill="x", pady=(12, 0))
        tk.Label(checklist, text=(
            "• Check installed apps for anything you don't recognize.\n"
            "• Check battery/data usage for unfamiliar apps running in the background.\n"
            "• Review account login-activity pages for unknown devices/locations.\n"
            "• Be cautious of anyone requesting AnyDesk/TeamViewer/screen-sharing access."
        ), font=("Consolas", 9), fg=GRAY, bg=PANEL, justify="left", wraplength=500).pack(anchor="w", padx=16, pady=(0, 16))

    def _run_surveillance_analysis(self, box, right):
        text = box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("Surveillance Check", "Describe what you've noticed first.")
            return
        result = engine.analyze(text)
        result["confidence_note"] = ("This is a pattern-based screening from your description, not a device-level "
                                      "malware scan. For a thorough check, use a reputable mobile security app.")
        render_result(right, result)

    # ========================================================
    # INCIDENT RESPONSE
    # ========================================================

    def create_incident_page(self):
        page = self.new_page("Incident Response")
        self.page_title(page, "INCIDENT RESPONSE", "OPEN A CASE, ADD EVIDENCE, ASK THE CASE AI ASSISTANT")

        top = tk.Frame(page, bg=BLACK)
        top.pack(fill="x", padx=35)

        self.case_id_var = tk.StringVar(value="No active case.")
        tk.Label(top, textvariable=self.case_id_var, font=("Consolas", 12, "bold"), fg=PURPLE_BRIGHT, bg=BLACK)\
            .pack(side="left")

        styled_button(top, "New Case", lambda: self._new_case()).pack(side="left", padx=10)
        styled_button(top, "Open Case", lambda: self._open_case_dialog(), bg=PANEL2).pack(side="left", padx=4)

        self.case_status_var = tk.StringVar(value="")
        status_menu = tk.OptionMenu(top, self.case_status_var, *STATUSES, command=lambda v: self._set_case_status(v))
        status_menu.configure(font=("Consolas", 8, "bold"), bg=PANEL2, fg=WHITE, relief="flat")
        status_menu.pack(side="right")

        wrap = tk.Frame(page, bg=BLACK)
        wrap.pack(fill="both", expand=True, padx=35, pady=(15, 25))

        left = tk.Frame(wrap, bg=BLACK)
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))
        right = tk.Frame(wrap, bg=BLACK, width=520)
        right.pack(side="left", fill="both")
        right.pack_propagate(False)

        add_section = Section(left, title="ADD EVIDENCE TO THIS CASE")
        add_section.pack(fill="x")
        desc_entry = labeled_entry(add_section, "Case description (what happened, overall)")
        styled_button(add_section, "Save Description", lambda: self._save_case_description(desc_entry), small=True, bg=PANEL2)\
            .pack(anchor="w", padx=16, pady=(0, 10))

        ev_row = tk.Frame(add_section, bg=PANEL)
        ev_row.pack(fill="x", padx=16, pady=(0, 16))
        for label, cmd in [
            ("+ URL", lambda: self._add_case_url()),
            ("+ Text", lambda: self._add_case_text()),
            ("+ Screenshot", lambda: self._add_case_image()),
            ("+ File", lambda: self._add_case_file()),
            ("+ QR", lambda: self._add_case_qr()),
            ("+ Email", lambda: self._add_case_email()),
        ]:
            styled_button(ev_row, label, cmd, small=True).pack(side="left", padx=4, pady=4)

        self.case_evidence_list = tk.Listbox(left, font=("Consolas", 9), bg=PANEL2, fg=WHITE,
                                              relief="flat", height=14, highlightthickness=0)
        self.case_evidence_list.pack(fill="both", expand=True, padx=0, pady=(12, 0))

        assistant_section = Section(right, title="AI CASE ASSISTANT")
        assistant_section.pack(fill="both", expand=True)
        self.assistant_output = tk.Text(assistant_section, font=("Consolas", 9), bg=PANEL2, fg=WHITE,
                                         relief="flat", height=18, wrap="word")
        self.assistant_output.pack(fill="both", expand=True, padx=16, pady=(0, 8))
        self.assistant_output.configure(state="disabled")

        q_row = tk.Frame(assistant_section, bg=PANEL)
        q_row.pack(fill="x", padx=16, pady=(0, 16))
        self.assistant_question_entry = tk.Entry(q_row, font=("Consolas", 9), bg=PANEL2, fg=WHITE,
                                                    insertbackground=WHITE, relief="flat")
        self.assistant_question_entry.pack(side="left", fill="x", expand=True, ipady=6)
        styled_button(q_row, "Ask", lambda: self._ask_case_assistant(), small=True).pack(side="left", padx=6)

        suggestions = tk.Frame(assistant_section, bg=PANEL)
        suggestions.pack(fill="x", padx=16, pady=(0, 12))
        for q in ["Summarize this case", "What should I do next?", "How do I report this?"]:
            styled_button(suggestions, q, lambda qq=q: self._ask_case_assistant(qq), small=True, bg=PANEL2)\
                .pack(side="left", padx=3, pady=3)

    def _refresh_case_view(self):
        if not self.current_case:
            self.case_id_var.set("No active case.")
            self.case_evidence_list.delete(0, "end")
            return
        c = self.current_case
        self.case_id_var.set(f"CASE {c.case_id} — {c.risk_level} ({c.risk_score}/100)")
        self.case_status_var.set(c.status)
        self.case_evidence_list.delete(0, "end")
        for ev in c.evidence:
            self.case_evidence_list.insert("end", f"[{ev['evidence_id']}] {ev['type'].upper()} — {ev.get('original_filename') or str(ev['data'])[:60]}")

    def _new_case(self):
        self.current_case = Case()
        self.current_case.save()
        self._refresh_case_view()
        messagebox.showinfo("Incident Response", f"New case created: {self.current_case.case_id}")

    def _open_case_dialog(self):
        case_id = simpledialog.askstring("Open Case", "Enter Case ID (e.g. SCAM-2026-123456):")
        if not case_id:
            return
        try:
            self.current_case = Case.load(case_id.strip())
            self._refresh_case_view()
        except FileNotFoundError:
            messagebox.showerror("Open Case", f"Case '{case_id}' was not found.")

    def _require_case(self):
        if not self.current_case:
            messagebox.showinfo("Incident Response", "Start or open a case first (click 'New Case').")
            return False
        return True

    def _save_case_description(self, entry):
        if not self._require_case():
            return
        self.current_case.description = entry.get().strip()
        self.current_case.add_timeline_event("Description updated.")
        self.current_case.save()
        self._refresh_case_view()

    def _add_case_url(self):
        if not self._require_case():
            return
        url = simpledialog.askstring("Add URL Evidence", "Paste the suspicious URL:")
        if not url:
            return
        score, indicators, categories, reasons = engine.analyze_url_indicators(url)
        level, color = engine.risk_level_from_score(score)
        analysis = {"score": score, "level": level, "color": color, "categories": categories,
                    "indicators": indicators, "reasons": reasons, "action": engine.recommended_action(level)}
        self.current_case.add_evidence("url", url, analysis=analysis)
        self.current_case.save()
        self._refresh_case_view()

    def _add_case_text(self):
        if not self._require_case():
            return
        text = simpledialog.askstring("Add Text Evidence", "Paste the message/text (this dialog is single-line; "
                                                             "for long text use AI Scam Detector then copy results):")
        if not text:
            return
        analysis = engine.analyze(text)
        self.current_case.add_evidence("text", text, analysis=analysis)
        self.current_case.save()
        self._refresh_case_view()

    def _add_case_image(self):
        if not self._require_case():
            return
        path = filedialog.askopenfilename(title="Add screenshot evidence",
                                           filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All files", "*.*")])
        if not path:
            return
        stored = store_uploaded_file(path)
        sha = file_tools.sha256_file(stored)
        shot = ocr_tools.analyze_screenshot(stored)
        analysis = engine.analyze(shot["ocr_text"]) if shot["ocr_text"] else {
            "score": 0, "level": "LOW RISK", "color": GREEN, "categories": ["NO TEXT EXTRACTED"],
            "indicators": [], "reasons": [shot["ocr_error"] or "No text extracted."], "action": "Manually review the image.",
        }
        self.current_case.add_evidence("image", stored, analysis=analysis,
                                        original_filename=os.path.basename(path), sha256=sha)
        self.current_case.save()
        self._refresh_case_view()

    def _add_case_file(self):
        if not self._require_case():
            return
        path = filedialog.askopenfilename(title="Add file evidence")
        if not path:
            return
        stored = store_uploaded_file(path)
        analysis = file_tools.analyze_file(stored, original_filename=os.path.basename(path))
        self.current_case.add_evidence("file", stored, analysis=analysis,
                                        original_filename=os.path.basename(path), sha256=analysis.get("sha256"))
        self.current_case.save()
        self._refresh_case_view()

    def _add_case_qr(self):
        if not self._require_case():
            return
        if not qr_tools.QR_AVAILABLE:
            messagebox.showwarning("QR Evidence", "QR decoding is unavailable (pyzbar not installed).")
            return
        path = filedialog.askopenfilename(title="Add QR code image",
                                           filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.webp"), ("All files", "*.*")])
        if not path:
            return
        stored = store_uploaded_file(path)
        payloads = qr_tools.decode_qr_image(stored)
        if not payloads:
            messagebox.showinfo("QR Evidence", "No QR code could be decoded from this image.")
            return
        info = qr_tools.analyze_qr_payload(payloads[0])
        ev_type = "payment_qr" if info["upi"] else "qr"
        self.current_case.add_evidence(ev_type, payloads[0], analysis=info,
                                        original_filename=os.path.basename(path))
        self.current_case.save()
        self._refresh_case_view()

    def _add_case_email(self):
        if not self._require_case():
            return
        raw = simpledialog.askstring("Add Email Evidence", "Paste sender address (or raw email, single line):")
        if not raw:
            return
        result = email_tools.analyze_email(sender=raw)
        self.current_case.add_evidence("email", raw, analysis=result)
        self.current_case.save()
        self._refresh_case_view()

    def _set_case_status(self, value):
        if not self.current_case:
            return
        self.current_case.set_status(value)
        self.current_case.save()
        self._refresh_case_view()

    def _ask_case_assistant(self, preset_question=None):
        if not self._require_case():
            return
        question = preset_question or self.assistant_question_entry.get().strip()
        if not question:
            return
        answer = self.current_case.ask_assistant(question)
        self.assistant_output.configure(state="normal")
        self.assistant_output.insert("end", f"You: {question}\n")
        self.assistant_output.insert("end", f"Assistant: {answer}\n\n")
        self.assistant_output.see("end")
        self.assistant_output.configure(state="disabled")
        self.assistant_question_entry.delete(0, "end")

    # ========================================================
    # EVIDENCE CREATOR
    # ========================================================

    def create_evidence_creator_page(self):
        page = self.new_page("Evidence Creator")
        self.page_title(page, "EVIDENCE CREATOR", "EXPORT A STRUCTURED, SHAREABLE EVIDENCE PACKAGE")

        wrap = tk.Frame(page, bg=BLACK)
        wrap.pack(fill="both", expand=True, padx=35, pady=(0, 25))

        section = Section(wrap, title="SELECT A CASE TO EXPORT")
        section.pack(fill="x")

        self.export_case_var = tk.StringVar(value="")
        self.export_case_menu_frame = tk.Frame(section, bg=PANEL)
        self.export_case_menu_frame.pack(fill="x", padx=16, pady=(0, 10))
        self._case_options = []
        self._export_dropdown = None
        self._refresh_case_dropdown()

        btn_row = tk.Frame(section, bg=PANEL)
        btn_row.pack(fill="x", padx=16, pady=(0, 16))
        styled_button(btn_row, "Refresh Case List", lambda: self._refresh_case_dropdown(), bg=PANEL2).pack(side="left")
        styled_button(btn_row, "Export Evidence Package", lambda: self._export_selected_case()).pack(side="left", padx=8)

        self.export_result_box = Section(wrap, title="EXPORT RESULT")
        self.export_result_box.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(self.export_result_box, text="No export yet.", font=("Consolas", 9), fg=GRAY, bg=PANEL)\
            .pack(anchor="w", padx=16, pady=(0, 16))

    def _refresh_case_dropdown(self):
        cases = Case.list_all()
        self._case_options = [c.case_id for c in cases] or ["(no cases yet)"]
        if self._export_dropdown:
            self._export_dropdown.destroy()
        self.export_case_var.set(self._case_options[0])
        self._export_dropdown = tk.OptionMenu(self.export_case_menu_frame, self.export_case_var, *self._case_options)
        self._export_dropdown.configure(font=("Consolas", 9), bg=PANEL2, fg=WHITE, relief="flat")
        self._export_dropdown.pack(anchor="w")

    def _export_selected_case(self):
        case_id = self.export_case_var.get()
        if not case_id or case_id == "(no cases yet)":
            messagebox.showinfo("Evidence Creator", "No case selected. Create a case in Incident Response first.")
            return
        try:
            case = Case.load(case_id)
        except FileNotFoundError:
            messagebox.showerror("Evidence Creator", f"Case '{case_id}' not found.")
            return

        out_dir = os.path.join(EXPORTS_DIR, case_id)
        paths = evidence_export.export_case(case, out_dir)

        for w in self.export_result_box.winfo_children():
            w.destroy()
        tk.Label(self.export_result_box, text=f"Exported case {case_id}:", font=("Consolas", 10, "bold"),
                  fg=BLUE_BRIGHT, bg=PANEL).pack(anchor="w", padx=16, pady=(0, 6))
        for label, key in [("JSON data", "json"), ("Text report", "txt"), ("PDF report", "pdf"), ("ZIP package", "zip")]:
            val = paths.get(key)
            text = f"{label}: {val}" if val else f"{label}: (not generated — missing optional dependency)"
            tk.Label(self.export_result_box, text=text, font=("Consolas", 9), fg=WHITE, bg=PANEL,
                      wraplength=900, justify="left").pack(anchor="w", padx=16, pady=1)

        styled_button(self.export_result_box, "Open Export Folder", lambda: self._open_folder(out_dir), bg=PANEL2)\
            .pack(anchor="w", padx=16, pady=(10, 16))

    def _open_folder(self, path):
        try:
            if os.name == "nt":
                os.startfile(path)
            elif os.uname().sysname == "Darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception:
            messagebox.showinfo("Evidence Creator", f"Files are located at:\n{path}")


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    root = tk.Tk()
    ScamHunt(root)
    root.mainloop()


if __name__ == "__main__":
    main()
