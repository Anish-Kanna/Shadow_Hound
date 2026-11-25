"""
Generate PS281 ShadowHound Presentation — Dark-themed PowerPoint
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ── Color Palette ─────────────────────────────────────────────────
BG_DARK      = RGBColor(0x0F, 0x17, 0x2A)
BG_CARD      = RGBColor(0x1A, 0x23, 0x3A)
BG_CARD_ALT  = RGBColor(0x15, 0x1E, 0x33)
ACCENT_BLUE  = RGBColor(0x3B, 0x82, 0xF6)
ACCENT_CYAN  = RGBColor(0x06, 0xB6, 0xD4)
ACCENT_PURPLE= RGBColor(0x8B, 0x5C, 0xF6)
ACCENT_GREEN = RGBColor(0x10, 0xB9, 0x81)
ACCENT_RED   = RGBColor(0xEF, 0x44, 0x44)
ACCENT_AMBER = RGBColor(0xF5, 0x9E, 0x0B)
TEXT_PRIMARY  = RGBColor(0xF1, 0xF5, 0xF9)
TEXT_SECONDARY= RGBColor(0x94, 0xA3, 0xB8)
TEXT_MUTED    = RGBColor(0x64, 0x74, 0x8B)
WHITE         = RGBColor(0xFF, 0xFF, 0xFF)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

SLIDE_W = prs.slide_width
SLIDE_H = prs.slide_height


def set_slide_bg(slide, color=BG_DARK):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_shape(slide, left, top, width, height, fill_color=BG_CARD, border_color=None, border_width=Pt(1), radius=None):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill_color
    if border_color:
        shape.line.color.rgb = border_color
        shape.line.width = border_width
    else:
        shape.line.fill.background()
    if radius is not None:
        shape.adjustments[0] = radius
    else:
        shape.adjustments[0] = 0.04
    return shape


def add_text(slide, left, top, width, height, text, font_size=18, color=TEXT_PRIMARY, bold=False, alignment=PP_ALIGN.LEFT, font_name="Calibri"):
    txbox = slide.shapes.add_textbox(left, top, width, height)
    tf = txbox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.font.name = font_name
    p.alignment = alignment
    return txbox


def add_multiline(slide, left, top, width, height, lines, default_size=16, default_color=TEXT_SECONDARY, line_spacing=1.5):
    """lines = list of (text, size, color, bold) tuples"""
    txbox = slide.shapes.add_textbox(left, top, width, height)
    tf = txbox.text_frame
    tf.word_wrap = True
    for i, line_data in enumerate(lines):
        if isinstance(line_data, str):
            text, size, color, bold = line_data, default_size, default_color, False
        else:
            text = line_data[0]
            size = line_data[1] if len(line_data) > 1 else default_size
            color = line_data[2] if len(line_data) > 2 else default_color
            bold = line_data[3] if len(line_data) > 3 else False
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = text
        p.font.size = Pt(size)
        p.font.color.rgb = color
        p.font.bold = bold
        p.font.name = "Calibri"
        p.space_after = Pt(size * (line_spacing - 1) * 2)
    return txbox


def add_accent_bar(slide, left, top, width, height, color=ACCENT_BLUE):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = color
    shape.line.fill.background()
    return shape


# ═══════════════════════════════════════════════════════════════════
# SLIDE 1 — TITLE
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
set_slide_bg(slide)

# Decorative accent circle
shape = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(9), Inches(-1.5), Inches(6), Inches(6))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x25, 0x40)
shape.line.fill.background()

# Tags
add_text(slide, Inches(1), Inches(1.2), Inches(8), Inches(0.4),
         "PS281  •  AI / Cybersecurity  •  Agentic Systems", 14, TEXT_MUTED, font_name="Consolas")

# Title
add_text(slide, Inches(1), Inches(1.8), Inches(10), Inches(1.2),
         "ShadowHound", 56, ACCENT_BLUE, bold=True)

add_text(slide, Inches(1), Inches(2.9), Inches(10), Inches(0.8),
         "AI-Powered Threat Hunting Agent", 32, TEXT_PRIMARY)

add_multiline(slide, Inches(1), Inches(3.8), Inches(8), Inches(1.2), [
    ("An agentic AI system for hypothesis-driven threat hunting", 18, TEXT_SECONDARY),
    ("using MITRE ATT&CK framework and Google Gemini LLM", 18, TEXT_SECONDARY),
])

# Tech stack badges
techs = ["Python 3.12", "FastAPI", "Google Gemini", "Celery + Redis", "React 18", "PostgreSQL"]
colors = [ACCENT_BLUE, ACCENT_PURPLE, ACCENT_CYAN, ACCENT_GREEN, ACCENT_AMBER, ACCENT_RED]
for i, (tech, clr) in enumerate(zip(techs, colors)):
    x = Inches(1) + Inches(i * 1.85)
    shape = add_shape(slide, x, Inches(5.2), Inches(1.7), Inches(0.45), BG_CARD, clr, Pt(1.5))
    add_text(slide, x, Inches(5.22), Inches(1.7), Inches(0.45),
             tech, 12, clr, bold=True, alignment=PP_ALIGN.CENTER, font_name="Consolas")


# ═══════════════════════════════════════════════════════════════════
# SLIDE 2 — PROBLEM STATEMENT
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_RED)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "Problem Statement", 36, TEXT_PRIMARY, bold=True)

add_text(slide, Inches(1.2), Inches(1.5), Inches(10), Inches(0.5),
         "Modern SOCs are overwhelmed. Proactive threat hunting is critical — but manual, expensive, and impossible to scale.",
         17, TEXT_SECONDARY)

# 3 stat cards
stats = [
    ("11,000+", "Alerts / day / SOC", "70% are false positives", ACCENT_BLUE),
    ("3.4 Million", "Cybersecurity talent gap", "ISC² 2023 Workforce Study", ACCENT_RED),
    ("204 Days", "Average dwell time", "IBM X-Force 2023", ACCENT_AMBER),
]
for i, (num, label, sub, clr) in enumerate(stats):
    x = Inches(1) + Inches(i * 3.8)
    add_shape(slide, x, Inches(2.2), Inches(3.5), Inches(2.0), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x, Inches(2.4), Inches(3.5), Inches(0.7), num, 40, clr, bold=True, alignment=PP_ALIGN.CENTER)
    add_text(slide, x, Inches(3.2), Inches(3.5), Inches(0.4), label, 14, TEXT_MUTED, alignment=PP_ALIGN.CENTER)
    add_text(slide, x, Inches(3.6), Inches(3.5), Inches(0.4), sub, 12, TEXT_MUTED, alignment=PP_ALIGN.CENTER)

# Pain + Solution boxes
add_accent_bar(slide, Inches(1), Inches(4.6), Inches(0.08), Inches(1.8), ACCENT_RED)
add_shape(slide, Inches(1), Inches(4.6), Inches(5.4), Inches(1.8), RGBColor(0x1C, 0x16, 0x16), RGBColor(0x3A, 0x20, 0x20))
add_multiline(slide, Inches(1.3), Inches(4.7), Inches(5), Inches(1.6), [
    ("⚠  The Core Pain", 18, ACCENT_RED, True),
    ("A single manual threat hunt takes 4–8 hours of a senior analyst's time — formulating hypotheses, writing queries across 6–10 platforms, correlating evidence, writing reports.", 14, TEXT_SECONDARY),
])

add_accent_bar(slide, Inches(6.8), Inches(4.6), Inches(0.08), Inches(1.8), ACCENT_GREEN)
add_shape(slide, Inches(6.8), Inches(4.6), Inches(5.5), Inches(1.8), RGBColor(0x12, 0x1E, 0x18), RGBColor(0x1A, 0x3A, 0x28))
add_multiline(slide, Inches(7.1), Inches(4.7), Inches(5), Inches(1.6), [
    ("✦  Our Solution", 18, ACCENT_GREEN, True),
    ("ShadowHound automates the entire hunt loop — hypothesis generation, query planning, evidence correlation — with human-in-the-loop governance.", 14, TEXT_SECONDARY),
])


# ═══════════════════════════════════════════════════════════════════
# SLIDE 3 — OBJECTIVES
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_CYAN)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "Objectives", 36, TEXT_PRIMARY, bold=True)

objectives = [
    ("🧠", "Automate Hypothesis Generation", "Use Google Gemini to generate ranked, MITRE ATT&CK-mapped threat hypotheses from analyst triggers or intel alerts", ACCENT_BLUE),
    ("📝", "Cross-Platform Query Planning", "Auto-generate queries in KQL (Microsoft), SPL (Splunk), FQL (CrowdStrike) for 10 integrated data sources", ACCENT_PURPLE),
    ("👤", "Human-in-the-Loop Approval", "No query executes on production systems without explicit analyst approval — governance & safety first", ACCENT_GREEN),
    ("🔍", "Evidence Aggregation & Scoring", "LLM-powered correlation of multi-source evidence with confidence scoring (0–100) and IOC extraction", ACCENT_CYAN),
    ("🔄", "Iterative OODA Hunt Loop", "Adaptive loop refines hypotheses based on evidence until confidence thresholds are met (max 5 iterations)", ACCENT_AMBER),
    ("📊", "Automated Hunt Reports", "Structured reports (PDF/JSON/MD) with MITRE mapping, threat timelines, IOC lists, and recommendations", ACCENT_RED),
]
for i, (icon, title, desc, clr) in enumerate(objectives):
    col = i % 3
    row = i // 3
    x = Inches(1) + Inches(col * 3.85)
    y = Inches(1.6) + Inches(row * 2.7)
    add_shape(slide, x, y, Inches(3.6), Inches(2.4), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x + Inches(0.2), y + Inches(0.15), Inches(0.5), Inches(0.5), icon, 28, clr)
    add_text(slide, x + Inches(0.2), y + Inches(0.65), Inches(3.2), Inches(0.5), title, 17, clr, bold=True)
    add_multiline(slide, x + Inches(0.2), y + Inches(1.1), Inches(3.2), Inches(1.2), [
        (desc, 13, TEXT_SECONDARY),
    ])


# ═══════════════════════════════════════════════════════════════════
# SLIDE 4 — LITERATURE SURVEY
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_PURPLE)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "Literature Survey", 36, TEXT_PRIMARY, bold=True)

# Table background
add_shape(slide, Inches(0.8), Inches(1.5), Inches(11.7), Inches(4.0), BG_CARD, RGBColor(0x25, 0x30, 0x48))

# Header row
headers = [("#", 0.4), ("Existing Work", 2.8), ("What It Does", 3.5), ("Limitation (Gap)", 4.5)]
hx = Inches(1)
for htxt, hw in headers:
    add_text(slide, hx, Inches(1.6), Inches(hw), Inches(0.4), htxt, 12, ACCENT_CYAN, bold=True)
    hx += Inches(hw)

lit_entries = [
    ("1", "Microsoft Copilot for Security (2024)", "LLM-powered assistant for Azure Sentinel", "Vendor-locked to Microsoft; reactive not proactive"),
    ("2", "Sqrrl / AWS (Oltsik, 2017)", "Threat hunting platform with link analysis", "No LLM integration; manual hypothesis only"),
    ("3", "MITRE ATT&CK Navigator (2018)", "Technique coverage mapping & visualization", "Visualization only — no query generation"),
    ("4", "IBM QRadar Advisor + Watson", "AI-assisted investigation using Watson NLP", "Limited to IBM QRadar ecosystem"),
    ("5", "Park et al. (2024) — ACM Survey", "\"LLMs for Cybersecurity\" — log parsing & triage", "Focus on log analysis, not agentic hunting"),
    ("6", "Shin et al. (2023) — IEEE Access", "Systematic review of hunting methodologies", "Theoretical framework; no automation"),
]
for i, (num, work, does, gap) in enumerate(lit_entries):
    y = Inches(2.1) + Inches(i * 0.55)
    hx = Inches(1)
    add_text(slide, hx, y, Inches(0.4), Inches(0.4), num, 13, TEXT_MUTED)
    hx += Inches(0.4)
    add_text(slide, hx, y, Inches(2.8), Inches(0.5), work, 13, TEXT_PRIMARY, bold=True)
    hx += Inches(2.8)
    add_text(slide, hx, y, Inches(3.5), Inches(0.5), does, 12, TEXT_SECONDARY)
    hx += Inches(3.5)
    add_text(slide, hx, y, Inches(4.5), Inches(0.5), gap, 12, ACCENT_AMBER)

# Gap statement box
add_accent_bar(slide, Inches(0.8), Inches(5.7), Inches(0.08), Inches(1.2), ACCENT_BLUE)
add_shape(slide, Inches(0.8), Inches(5.7), Inches(11.7), Inches(1.2), RGBColor(0x12, 0x18, 0x2A), RGBColor(0x25, 0x45, 0x80))
add_multiline(slide, Inches(1.1), Inches(5.8), Inches(11), Inches(1.0), [
    ("🎯  The Gap", 18, ACCENT_BLUE, True),
    ("No existing tool provides a vendor-agnostic, agentic AI that autonomously generates hypotheses, plans queries across multiple platforms, maintains human oversight, and iteratively refines its investigation in an OODA loop.", 14, TEXT_SECONDARY),
])


# ═══════════════════════════════════════════════════════════════════
# SLIDE 5 — SYSTEM ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_BLUE)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "System Architecture", 36, TEXT_PRIMARY, bold=True)

# Architecture flow — left side
arch_items = [
    ("🧑‍💻  Analyst / Scheduler / Intel Alert", ACCENT_BLUE, 0),
    ("🧠  Hypothesis Engine (Google Gemini LLM)", ACCENT_PURPLE, 1),
    ("📝  Query Planner → 🛡 Safety Validator → ✅ Approval Gate", ACCENT_CYAN, 2),
    ("⚡  Query Execution & Dispatch", ACCENT_GREEN, 4),
    ("🔬  Evidence Aggregator + Confidence Scorer (LLM)", ACCENT_GREEN, 5),
    ("🔄  OODA Loop Decision (continue or report?)", ACCENT_AMBER, 6),
    ("📋  Hunt Report (PDF / JSON / Markdown)", ACCENT_RED, 7),
]

for text, clr, idx in arch_items:
    y = Inches(1.5) + Inches(idx * 0.72)
    cr, cg, cb = clr[0], clr[1], clr[2]
    box_color = RGBColor(cr // 4, cg // 4, cb // 4)
    border = RGBColor(cr // 2, cg // 2, cb // 2)
    add_shape(slide, Inches(1), y, Inches(7.5), Inches(0.55), box_color, border)
    add_text(slide, Inches(1.2), y + Inches(0.05), Inches(7), Inches(0.45), text, 14, clr, bold=True, alignment=PP_ALIGN.CENTER)
    # Arrow
    if idx < 7:
        add_text(slide, Inches(4.5), y + Inches(0.5), Inches(0.5), Inches(0.3), "↓", 14, TEXT_MUTED, alignment=PP_ALIGN.CENTER)

# Data sources row (between planning and execution)
sources = [("CrowdStrike", ACCENT_RED), ("Splunk", ACCENT_AMBER), ("Sentinel", ACCENT_BLUE), ("VirusTotal", ACCENT_GREEN), ("MISP", ACCENT_PURPLE)]
y_sources = Inches(1.5) + Inches(3 * 0.72)
for i, (src, clr) in enumerate(sources):
    sx = Inches(1) + Inches(i * 1.55)
    add_shape(slide, sx, y_sources, Inches(1.4), Inches(0.45), BG_CARD, clr, Pt(1))
    add_text(slide, sx, y_sources + Inches(0.03), Inches(1.4), Inches(0.4), src, 11, clr, bold=True, alignment=PP_ALIGN.CENTER, font_name="Consolas")

# Right side — info cards
rx = Inches(9)
# Tech Stack
add_shape(slide, rx, Inches(1.5), Inches(3.5), Inches(1.5), BG_CARD, RGBColor(0x25, 0x30, 0x48))
add_text(slide, rx + Inches(0.2), Inches(1.55), Inches(3), Inches(0.35), "Tech Stack", 15, ACCENT_CYAN, bold=True)
add_multiline(slide, rx + Inches(0.2), Inches(1.9), Inches(3), Inches(1.0), [
    ("Python 3.12 · FastAPI · Celery", 12, TEXT_SECONDARY),
    ("Google Gemini · React 18", 12, TEXT_SECONDARY),
    ("PostgreSQL · HashiCorp Vault", 12, TEXT_SECONDARY),
    ("OpenTelemetry · Grafana", 12, TEXT_SECONDARY),
])

# Integrations
add_shape(slide, rx, Inches(3.2), Inches(3.5), Inches(1.5), BG_CARD, RGBColor(0x25, 0x30, 0x48))
add_text(slide, rx + Inches(0.2), Inches(3.25), Inches(3), Inches(0.35), "10 Integrations", 15, ACCENT_CYAN, bold=True)
add_multiline(slide, rx + Inches(0.2), Inches(3.6), Inches(3), Inches(1.0), [
    ("EDR: CrowdStrike, SentinelOne, Defender", 12, TEXT_SECONDARY),
    ("SIEM: Splunk, Sentinel, Elastic", 12, TEXT_SECONDARY),
    ("Intel: MISP, VirusTotal, OpenCTI", 12, TEXT_SECONDARY),
    ("+ 5 built-in YAML playbooks", 12, ACCENT_GREEN),
])

# Database
add_shape(slide, rx, Inches(4.9), Inches(3.5), Inches(1.2), BG_CARD, RGBColor(0x25, 0x30, 0x48))
add_text(slide, rx + Inches(0.2), Inches(4.95), Inches(3), Inches(0.35), "Database: 8 Tables", 15, ACCENT_CYAN, bold=True)
add_multiline(slide, rx + Inches(0.2), Inches(5.3), Inches(3), Inches(0.7), [
    ("Users · HuntSessions · Hypotheses", 12, TEXT_SECONDARY),
    ("PlannedQueries · Evidence · Reports", 12, TEXT_SECONDARY),
    ("AuditLogs · ThreatIntelCache", 12, TEXT_SECONDARY),
])


# ═══════════════════════════════════════════════════════════════════
# SLIDE 6 — METHODOLOGY: 7-PHASE HUNT LOOP
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_GREEN)
add_text(slide, Inches(1.2), Inches(0.75), Inches(10), Inches(0.6), "Methodology — 7-Phase OODA Hunt Loop", 36, TEXT_PRIMARY, bold=True)

phases = [
    ("1", "Hypothesize", "Gemini generates 3–5 ranked hypotheses mapped to MITRE ATT&CK tactics & techniques", ACCENT_BLUE, "hypothesis_engine.py"),
    ("2", "Plan Queries", "LLM writes platform-specific queries (KQL, SPL, FQL) — each passes safety validation", ACCENT_PURPLE, "query_planner.py"),
    ("3", "Approval Gate", "Human analyst reviews & approves/rejects — RBAC enforced (approver/admin only)", ACCENT_GREEN, "api/routers/queries.py"),
    ("4", "Execute Queries", "Approved queries dispatched to EDR / SIEM / Intel via integration dispatcher", ACCENT_CYAN, "integrations/dispatcher.py"),
    ("5", "Analyze Evidence", "LLM classifies evidence (confirming/contradicting/neutral), extracts IOCs, scores 0–100", ACCENT_AMBER, "evidence_aggregator.py"),
    ("6", "Loop Decision", "Confidence < 70% & iterations < 5 → loop back. IR escalation if critical threat.", ACCENT_RED, "orchestrator.py"),
    ("7", "Report", "Structured report (PDF/JSON/MD): executive summary, IOCs, timeline, MITRE mapping", RGBColor(0xA7, 0x8B, 0xFA), "report_builder.py"),
]

for i, (num, title, desc, clr, module) in enumerate(phases):
    col = 0 if i < 4 else 1
    row = i if i < 4 else i - 4
    x = Inches(1) + Inches(col * 6)
    y = Inches(1.5) + Inches(row * 1.4)

    # Number circle
    circle = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y + Inches(0.05), Inches(0.45), Inches(0.45))
    circle.fill.solid()
    circle.fill.fore_color.rgb = clr
    circle.line.fill.background()
    circle.adjustments[0] = 0.3
    add_text(slide, x + Inches(0.02), y + Inches(0.05), Inches(0.45), Inches(0.45), num, 18, WHITE, bold=True, alignment=PP_ALIGN.CENTER)

    # Title + description
    add_text(slide, x + Inches(0.6), y, Inches(4.5), Inches(0.35), title, 18, TEXT_PRIMARY, bold=True)
    add_text(slide, x + Inches(0.6), y + Inches(0.35), Inches(5), Inches(0.5), desc, 13, TEXT_SECONDARY)
    add_text(slide, x + Inches(0.6), y + Inches(0.8), Inches(3), Inches(0.3), module, 11, TEXT_MUTED, font_name="Consolas")

# OODA note box
add_shape(slide, Inches(7), Inches(5.7), Inches(5.5), Inches(1.0), RGBColor(0x1E, 0x1A, 0x10), RGBColor(0x4A, 0x3A, 0x10))
add_multiline(slide, Inches(7.2), Inches(5.8), Inches(5), Inches(0.8), [
    ("🔄  OODA: Observe → Orient → Decide → Act", 15, ACCENT_AMBER, True),
    ("The hunt iterates until confidence ≥ 70% or max 5 iterations reached.", 13, TEXT_SECONDARY),
])


# ═══════════════════════════════════════════════════════════════════
# SLIDE 7 — SECURITY & SAFETY
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_RED)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "Security & Safety Design", 36, TEXT_PRIMARY, bold=True)

add_text(slide, Inches(1.2), Inches(1.4), Inches(10), Inches(0.5),
         "Every layer of ShadowHound is designed with security-first principles", 17, TEXT_SECONDARY)

sec_cards = [
    ("🛡️  Query Safety Validation", [
        "Regex blocklist: DROP, DELETE, TRUNCATE, EXEC",
        "SPL blocked: | outputlookup, | collect, | sendemail",
        "KQL blocked: | invoke operator",
        "Validates BEFORE reaching approval gate",
    ], ACCENT_RED, 0, 0),
    ("🔐  Authentication & RBAC", [
        "JWT-based authentication (access + refresh tokens)",
        "Three roles: analyst → approver → admin",
        "Role hierarchy enforced via FastAPI dependencies",
        "bcrypt password hashing via passlib",
    ], ACCENT_BLUE, 1, 0),
    ("📜  Immutable Audit Log", [
        "Every action logged with full context",
        "User ID, timestamp, payload hash, IP, user-agent",
        "Append-only — no edits or deletions",
        "Admin-only access to audit log API",
    ], ACCENT_GREEN, 0, 1),
    ("🧬  LLM Safety", [
        "Structured JSON schemas constrain output",
        "External data in separate message fields",
        "Anti prompt-injection architecture",
        "No raw security data persisted to DB",
    ], ACCENT_PURPLE, 1, 1),
]

for title, items, clr, col, row in sec_cards:
    x = Inches(1) + Inches(col * 5.8)
    y = Inches(2.0) + Inches(row * 2.7)
    add_shape(slide, x, y, Inches(5.5), Inches(2.4), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x + Inches(0.2), y + Inches(0.1), Inches(5), Inches(0.4), title, 17, clr, bold=True)
    lines = [(f"▸  {item}", 13, TEXT_SECONDARY) for item in items]
    add_multiline(slide, x + Inches(0.25), y + Inches(0.55), Inches(5), Inches(1.8), lines, line_spacing=1.4)


# ═══════════════════════════════════════════════════════════════════
# SLIDE 8 — HUNT LIFECYCLE
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_AMBER)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "Hunt Session Lifecycle", 36, TEXT_PRIMARY, bold=True)

# Lifecycle flow
states_row1 = [
    ("PENDING", TEXT_MUTED),
    ("HYPOTHESIZING", ACCENT_PURPLE),
    ("PLANNING", ACCENT_BLUE),
    ("AWAITING_APPROVAL", ACCENT_AMBER),
]
states_row2 = [
    ("EXECUTING", ACCENT_CYAN),
    ("ANALYZING", ACCENT_GREEN),
    ("↻ Loop?", ACCENT_RED),
    ("REPORTING", ACCENT_BLUE),
    ("✓ COMPLETED", ACCENT_GREEN),
]

for i, (state, clr) in enumerate(states_row1):
    x = Inches(0.8) + Inches(i * 3.1)
    border = RGBColor(clr[0] // 2, clr[1] // 2, clr[2] // 2)
    bg = RGBColor(clr[0] // 5, clr[1] // 5, clr[2] // 5)
    add_shape(slide, x, Inches(2.0), Inches(2.6), Inches(0.6), bg, border)
    add_text(slide, x, Inches(2.05), Inches(2.6), Inches(0.55), state, 14, clr, bold=True, alignment=PP_ALIGN.CENTER, font_name="Consolas")
    if i < 3:
        add_text(slide, x + Inches(2.6), Inches(2.05), Inches(0.5), Inches(0.55), "→", 18, TEXT_MUTED, alignment=PP_ALIGN.CENTER)

add_text(slide, Inches(6), Inches(2.7), Inches(1), Inches(0.5), "↓", 22, TEXT_MUTED, alignment=PP_ALIGN.CENTER)

for i, (state, clr) in enumerate(states_row2):
    x = Inches(0.5) + Inches(i * 2.55)
    border = RGBColor(clr[0] // 2, clr[1] // 2, clr[2] // 2)
    bg = RGBColor(clr[0] // 5, clr[1] // 5, clr[2] // 5)
    w = Inches(2.2) if state != "✓ COMPLETED" else Inches(2.2)
    add_shape(slide, x, Inches(3.3), w, Inches(0.6), bg, border)
    add_text(slide, x, Inches(3.35), w, Inches(0.55), state, 13, clr, bold=True, alignment=PP_ALIGN.CENTER, font_name="Consolas")
    if i < 4:
        add_text(slide, x + w, Inches(3.35), Inches(0.35), Inches(0.55), "→", 16, TEXT_MUTED, alignment=PP_ALIGN.CENTER)

# Stats
stat_data = [
    ("10", "Status States", ACCENT_PURPLE),
    ("56/56", "Tests Passing ✅", ACCENT_GREEN),
    ("8", "Database Tables", ACCENT_CYAN),
    ("15+", "API Endpoints", ACCENT_BLUE),
    ("5", "Hunt Playbooks", ACCENT_AMBER),
    ("10", "Integrations", ACCENT_RED),
]
for i, (num, label, clr) in enumerate(stat_data):
    x = Inches(0.8) + Inches(i * 2.05)
    add_shape(slide, x, Inches(4.6), Inches(1.85), Inches(1.6), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x, Inches(4.8), Inches(1.85), Inches(0.6), num, 36, clr, bold=True, alignment=PP_ALIGN.CENTER)
    add_text(slide, x, Inches(5.4), Inches(1.85), Inches(0.4), label, 12, TEXT_MUTED, alignment=PP_ALIGN.CENTER)


# ═══════════════════════════════════════════════════════════════════
# SLIDE 9 — EXPECTED OUTCOMES
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_GREEN)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "Expected Outcomes", 36, TEXT_PRIMARY, bold=True)

outcomes = [
    ("⚡", "70–80% Time Reduction", "Manual hunt: 4–8 hours → ShadowHound: ~30 min analyst review", ACCENT_BLUE),
    ("🌐", "Cross-Platform Hunting", "One hunt session queries CrowdStrike, Splunk, Sentinel, VirusTotal, MISP simultaneously", ACCENT_PURPLE),
    ("🎯", "Consistent MITRE ATT&CK Coverage", "Every hypothesis mapped to techniques (T1059.001, T1078) — no coverage gaps", ACCENT_CYAN),
    ("📋", "Auditable, Governed Hunting", "Complete audit trail — every action, approval, evidence correlation is logged", ACCENT_GREEN),
    ("📊", "Structured Hunt Reports", "PDF / JSON / MD with executive summary, IOC lists, threat timeline, MITRE mapping", ACCENT_AMBER),
    ("🔄", "Iterative Refinement", "OODA loop ensures investigations dig deeper — doesn't stop at surface-level findings", ACCENT_RED),
]

for i, (icon, title, desc, clr) in enumerate(outcomes):
    col = i % 2
    row = i // 2
    x = Inches(1) + Inches(col * 5.8)
    y = Inches(1.5) + Inches(row * 1.85)
    add_shape(slide, x, y, Inches(5.5), Inches(1.6), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x + Inches(0.2), y + Inches(0.15), Inches(0.5), Inches(0.5), icon, 28, clr)
    add_text(slide, x + Inches(0.8), y + Inches(0.15), Inches(4.5), Inches(0.4), title, 18, clr, bold=True)
    add_text(slide, x + Inches(0.8), y + Inches(0.6), Inches(4.5), Inches(0.8), desc, 14, TEXT_SECONDARY)


# ═══════════════════════════════════════════════════════════════════
# SLIDE 10 — DEMONSTRATION
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)
add_accent_bar(slide, Inches(1), Inches(0.8), Inches(0.08), Inches(0.5), ACCENT_CYAN)
add_text(slide, Inches(1.2), Inches(0.75), Inches(8), Inches(0.6), "Live Demonstration", 36, TEXT_PRIMARY, bold=True)

demo_steps = [
    ("1️⃣", "API & Swagger Docs", "uvicorn main:app --reload --port 8000\n→ http://localhost:8000/docs", "Interactive API with 15+ endpoints"),
    ("2️⃣", "Authentication Flow", 'POST /api/v1/auth/login\n{"email":"admin@ps281.dev","password":"..."}\n→ Returns JWT tokens', "JWT access + refresh token pair"),
    ("3️⃣", "Create Hunt Session", 'POST /api/v1/hunts\n{"title":"Lateral Movement Hunt",\n "trigger_type":"analyst_request"}', "Hunt created with status PENDING"),
]

demo_steps2 = [
    ("4️⃣", "Test Results", "$ pytest tests/ -v\n56 passed ✅ in 12.4s", "37 unit + 19 integration tests"),
    ("5️⃣", "Project Structure", "agent/    → LLM engines (4 modules)\napi/      → REST endpoints & auth\nintegrations/ → 10 data sources\ndb/       → 8 SQLAlchemy models", "Clean, modular architecture"),
    ("6️⃣", "Hunting Playbooks", "5 built-in YAML playbooks:\nWMI Lateral Movement\nCredential Dumping\nRansomware • Phishing • Persistence", "MITRE ATT&CK mapped"),
]

for i, (num, title, code, note) in enumerate(demo_steps):
    x = Inches(0.8)
    y = Inches(1.5) + Inches(i * 1.9)
    add_shape(slide, x, y, Inches(5.8), Inches(1.7), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x + Inches(0.15), y + Inches(0.1), Inches(5.5), Inches(0.35), f"{num}  {title}", 16, ACCENT_CYAN, bold=True)
    add_multiline(slide, x + Inches(0.2), y + Inches(0.45), Inches(5.3), Inches(0.9), [
        (code, 11, TEXT_SECONDARY),
    ])
    add_text(slide, x + Inches(0.2), y + Inches(1.3), Inches(5.3), Inches(0.3), note, 12, TEXT_MUTED)

for i, (num, title, code, note) in enumerate(demo_steps2):
    x = Inches(6.8)
    y = Inches(1.5) + Inches(i * 1.9)
    add_shape(slide, x, y, Inches(5.8), Inches(1.7), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x + Inches(0.15), y + Inches(0.1), Inches(5.5), Inches(0.35), f"{num}  {title}", 16, ACCENT_CYAN, bold=True)
    add_multiline(slide, x + Inches(0.2), y + Inches(0.45), Inches(5.3), Inches(0.9), [
        (code, 11, TEXT_SECONDARY),
    ])
    add_text(slide, x + Inches(0.2), y + Inches(1.3), Inches(5.3), Inches(0.3), note, 12, TEXT_MUTED)


# ═══════════════════════════════════════════════════════════════════
# SLIDE 11 — THANK YOU
# ═══════════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_bg(slide)

# Decorative circle
shape = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(4.5), Inches(-2), Inches(8), Inches(8))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x15, 0x20, 0x38)
shape.line.fill.background()

add_text(slide, Inches(0), Inches(1.8), SLIDE_W, Inches(1), "Thank You", 56, ACCENT_BLUE, bold=True, alignment=PP_ALIGN.CENTER)

add_multiline(slide, Inches(2.5), Inches(3.0), Inches(8.3), Inches(1.0), [
    ("ShadowHound brings agentic AI to proactive cybersecurity,", 20, TEXT_SECONDARY),
    ("keeping humans in the loop where it matters most.", 20, TEXT_SECONDARY),
])

# Bottom cards
pillars = [
    ("🧠", "LLM-Powered\nHypothesis Generation"),
    ("🛡️", "Human-in-the-Loop\nGovernance"),
    ("🔄", "Iterative OODA\nHunt Loop"),
    ("📊", "Automated\nHunt Reports"),
]
for i, (icon, label) in enumerate(pillars):
    x = Inches(1.5) + Inches(i * 2.8)
    add_shape(slide, x, Inches(4.5), Inches(2.4), Inches(1.6), BG_CARD, RGBColor(0x25, 0x30, 0x48))
    add_text(slide, x, Inches(4.6), Inches(2.4), Inches(0.5), icon, 28, TEXT_PRIMARY, alignment=PP_ALIGN.CENTER)
    add_text(slide, x + Inches(0.1), Inches(5.15), Inches(2.2), Inches(0.8), label, 13, TEXT_MUTED, alignment=PP_ALIGN.CENTER)

add_text(slide, Inches(0), Inches(6.5), SLIDE_W, Inches(0.5), "Questions?", 22, TEXT_MUTED, alignment=PP_ALIGN.CENTER)


# ── SAVE ──────────────────────────────────────────────────────────
output_path = r"c:\Users\anish\Desktop\ps281\ShadowHound_Presentation.pptx"
prs.save(output_path)
print(f"[OK] Presentation saved to: {output_path}")
print(f"   Slides: {len(prs.slides)}")
