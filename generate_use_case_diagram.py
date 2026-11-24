"""
Generate High-Resolution UML Use Case Diagram PNG for SecureShield AI.
"""
import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, Ellipse

# Set up figure with high resolution
fig = plt.figure(figsize=(22, 14), dpi=300)
ax = fig.add_subplot(111)
ax.set_xlim(0, 22)
ax.set_ylim(0, 14)
ax.axis("off")

# Color Palette (Enterprise Cyber Theme)
BG_COLOR = "#0D1117"        # Dark slate background
PANEL_BG = "#161B22"        # Dark card background
SYSTEM_BORDER = "#30363D"   # Border color
CYAN = "#00D2FF"            # Primary cyber accent
EMERALD = "#00E676"         # Safe / secondary
AMBER = "#FFB300"           # Warning / background service
PURPLE = "#A371F7"          # External APIs
CORAL = "#FF5252"           # Threat detection
TEXT_WHITE = "#F0F6FC"      # Clean white text
TEXT_MUTED = "#8B949E"      # Subtitle / note text
ARROW_COLOR = "#58A6FF"     # Association arrow

fig.patch.set_facecolor(BG_COLOR)
ax.set_facecolor(BG_COLOR)

# Title & Subtitle Header
plt.text(11, 13.4, "SecureShield AI — UML Use Case Diagram", 
         fontsize=22, fontweight="bold", color=TEXT_WHITE, ha="center", va="center")
plt.text(11, 13.0, "Mobile Defense System & Multi-Engine Threat Detection Platform", 
         fontsize=12, color=CYAN, ha="center", va="center", style="italic")

# Draw System Boundary
system_rect = FancyBboxPatch((4.2, 0.6), 13.6, 12.0,
                             boxstyle="round,pad=0.2,rounding_size=0.3",
                             facecolor=PANEL_BG, edgecolor=CYAN, linewidth=2.0, alpha=0.95)
ax.add_patch(system_rect)

# System Boundary Label
plt.text(4.6, 12.3, "System Boundary: SecureShield AI Mobile & Defense Backend", 
         fontsize=13, fontweight="bold", color=CYAN, ha="left", va="center")

# Helper to draw Actor
def draw_actor(x, y, name, role_type="Primary Actor", color=CYAN):
    # Head
    head = plt.Circle((x, y + 0.6), 0.22, edgecolor=color, facecolor=BG_COLOR, linewidth=2.5, zorder=5)
    ax.add_patch(head)
    # Body
    ax.plot([x, x], [y + 0.38, y - 0.15], color=color, linewidth=2.5, zorder=5)
    # Arms
    ax.plot([x - 0.35, x + 0.35], [y + 0.2, y + 0.2], color=color, linewidth=2.5, zorder=5)
    # Legs
    ax.plot([x, x - 0.3], [y - 0.15, y - 0.6], color=color, linewidth=2.5, zorder=5)
    ax.plot([x, x + 0.3], [y - 0.15, y - 0.6], color=color, linewidth=2.5, zorder=5)
    # Label
    plt.text(x, y - 0.85, name, fontsize=10.5, fontweight="bold", color=TEXT_WHITE, ha="center", va="top", zorder=5)
    plt.text(x, y - 1.15, f"«{role_type}»", fontsize=8.5, color=TEXT_MUTED, ha="center", va="top", zorder=5)

# Helper to draw Use Case Oval
use_cases = {}
def draw_use_case(key, cx, cy, w, h, text, category="core", font_size=9.5):
    colors = {
        "client": (PANEL_BG, CYAN),
        "engine": ("#1C2128", CORAL),
        "fusion": ("#1F242C", EMERALD),
        "mgmt": ("#21262D", AMBER),
        "external": ("#252033", PURPLE)
    }
    bg, border = colors.get(category, (PANEL_BG, CYAN))
    ellipse = Ellipse((cx, cy), w, h, facecolor=bg, edgecolor=border, linewidth=1.8, zorder=4)
    ax.add_patch(ellipse)
    plt.text(cx, cy, text, fontsize=font_size, color=TEXT_WHITE, ha="center", va="center", 
             fontweight="semibold", zorder=5, multialignment="center")
    use_cases[key] = (cx, cy, w, h)

# ----------------- DRAW ACTORS -----------------
# Left Actors (Users & Mobile OS)
draw_actor(2.0, 9.8, "Mobile End User", "Human User", CYAN)
draw_actor(2.0, 4.2, "Android OS\n(Accessibility & WorkManager)", "System Actor", AMBER)

# Right Actors (External Services)
draw_actor(20.0, 9.8, "Google Cloud\n& OAuth Services", "Identity / Gmail Provider", PURPLE)
draw_actor(20.0, 4.2, "Threat Intelligence\nAPIs & Feeds", "External Security Feeds", PURPLE)


# ----------------- DRAW USE CASES -----------------

# Column 1: Client Ingestion & Interaction (x ~ 6.5)
draw_use_case("UC_AUTH", 6.8, 11.2, 3.4, 0.95, "UC1: Biometric & Multi-Factor\nAuthentication / Auto-Provision", "mgmt", 8.5)
draw_use_case("UC_MANUAL", 6.8, 9.6, 3.4, 0.95, "UC2: Manual URL / Text\nThreat Scan", "client", 8.5)
draw_use_case("UC_SHARE", 6.8, 8.0, 3.4, 0.95, "UC3: Share Link / File from\nThird-Party Apps (ShareSheet)", "client", 8.5)
draw_use_case("UC_GUARDIAN", 6.8, 6.4, 3.4, 0.95, "UC4: Real-Time Screen\nThreat Interception (Guardian)", "client", 8.5)
draw_use_case("UC_GMAIL", 6.8, 4.8, 3.4, 0.95, "UC5: Synchronize & Inspect\nUnread Gmail Inbox", "client", 8.5)
draw_use_case("UC_BG_SCAN", 6.8, 3.2, 3.4, 0.95, "UC6: Background Inbox\nMonitoring (WorkManager)", "client", 8.5)
draw_use_case("UC_HISTORY", 6.8, 1.6, 3.4, 0.95, "UC7: View / Manage Offline\nLocal Scan History", "mgmt", 8.5)

# Column 2: Backend Engines & Processing (x ~ 11.0)
draw_use_case("UC_PREPROC", 11.0, 8.8, 3.5, 0.95, "UC8: Input Normalization\n& URL Unshortening", "engine", 8.5)
draw_use_case("UC_ENGINES", 11.0, 6.8, 3.7, 1.15, "UC9: Multi-Engine Threat\nInspection (7 Engines:\nLexical, Malware, NLP, Sender,\nHeader, Attachment, Visual)", "engine", 8.0)
draw_use_case("UC_FEEDBACK", 11.0, 1.6, 3.4, 0.95, "UC10: Submit Scan Accuracy\nFeedback & Telemetry", "mgmt", 8.5)

# Column 3: Fusion, Intelligence & External Feeds (x ~ 15.2)
draw_use_case("UC_FUSION", 15.2, 8.8, 3.5, 1.0, "UC11: Confidence-Weighted\nRisk Fusion (0-100 Score)", "fusion", 8.5)
draw_use_case("UC_EXPLAIN", 15.2, 6.8, 3.5, 1.0, "UC12: Generate Threat Reasoning\n& Remediation Advice", "fusion", 8.5)
draw_use_case("UC_THREAT_FEEDS", 15.2, 3.6, 3.6, 1.0, "UC13: Synchronize Threat Feeds\n(URLhaus, OpenPhish, Bazaar)", "external", 8.5)


# ----------------- DRAW CONNECTORS & RELATIONSHIPS -----------------

def draw_line(p1, p2, color=ARROW_COLOR, style="-", width=1.5, zorder=3):
    ax.plot([p1[0], p2[0]], [p1[1], p2[1]], linestyle=style, color=color, linewidth=width, zorder=zorder)

def draw_include(uc_from, uc_to, label="«include»"):
    x1, y1, w1, h1 = use_cases[uc_from]
    x2, y2, w2, h2 = use_cases[uc_to]
    # calculate points
    dx = x2 - x1
    dy = y2 - y1
    dist = (dx**2 + dy**2)**0.5
    start_x = x1 + (dx / dist) * (w1 / 2)
    start_y = y1 + (dy / dist) * (h1 / 2)
    end_x = x2 - (dx / dist) * (w2 / 2)
    end_y = y2 - (dy / dist) * (h2 / 2)
    
    ax.annotate("", xy=(end_x, end_y), xytext=(start_x, start_y),
                arrowprops=dict(arrowstyle="->", color="#79C0FF", linestyle="--", lw=1.3),
                zorder=4)
    # text label
    mid_x = (start_x + end_x) / 2
    mid_y = (start_y + end_y) / 2 + 0.15
    plt.text(mid_x, mid_y, label, fontsize=7.5, color="#79C0FF", style="italic", ha="center", va="bottom", zorder=6)

def draw_extend(uc_from, uc_to, label="«extend»"):
    x1, y1, w1, h1 = use_cases[uc_from]
    x2, y2, w2, h2 = use_cases[uc_to]
    dx = x2 - x1
    dy = y2 - y1
    dist = (dx**2 + dy**2)**0.5
    start_x = x1 + (dx / dist) * (w1 / 2)
    start_y = y1 + (dy / dist) * (h1 / 2)
    end_x = x2 - (dx / dist) * (w2 / 2)
    end_y = y2 - (dy / dist) * (h2 / 2)
    
    ax.annotate("", xy=(end_x, end_y), xytext=(start_x, start_y),
                arrowprops=dict(arrowstyle="->", color=EMERALD, linestyle="--", lw=1.3),
                zorder=4)
    mid_x = (start_x + end_x) / 2
    mid_y = (start_y + end_y) / 2 + 0.15
    plt.text(mid_x, mid_y, label, fontsize=7.5, color=EMERALD, style="italic", ha="center", va="bottom", zorder=6)

# User Associations
draw_line((2.4, 9.8), (5.1, 11.2))   # User -> UC1 (Auth)
draw_line((2.4, 9.8), (5.1, 9.6))    # User -> UC2 (Manual Scan)
draw_line((2.4, 9.8), (5.1, 8.0))    # User -> UC3 (Share)
draw_line((2.4, 9.8), (5.1, 4.8))    # User -> UC5 (Gmail)
draw_line((2.4, 9.8), (5.1, 1.6))    # User -> UC7 (History)

# OS / Background Actor Associations
draw_line((2.4, 4.2), (5.1, 6.4), color=AMBER)    # OS -> UC4 (Guardian)
draw_line((2.4, 4.2), (5.1, 3.2), color=AMBER)    # OS -> UC6 (Background Scan)

# Right Actor Associations
# Google Cloud -> UC1 & UC5
draw_line((19.6, 9.8), (8.5, 11.2), color=PURPLE)   # Google -> UC1
draw_line((19.6, 9.8), (8.5, 4.8), color=PURPLE)    # Google -> UC5

# Threat Intel APIs -> UC9 & UC13
draw_line((19.6, 4.2), (12.8, 6.8), color=PURPLE)   # Intel -> UC9 (Engines: SafeBrowsing / VirusTotal)
draw_line((19.6, 4.2), (17.0, 3.6), color=PURPLE)   # Intel -> UC13 (Feed Sync)

# Include Relationships (Core Pipeline)
draw_include("UC_MANUAL", "UC_PREPROC")
draw_include("UC_SHARE", "UC_PREPROC")
draw_include("UC_GUARDIAN", "UC_PREPROC")
draw_include("UC_GMAIL", "UC_PREPROC")
draw_include("UC_BG_SCAN", "UC_PREPROC")

draw_include("UC_PREPROC", "UC_ENGINES")
draw_include("UC_ENGINES", "UC_FUSION")
draw_include("UC_FUSION", "UC_EXPLAIN")

# Extend Relationships
draw_extend("UC_FEEDBACK", "UC_HISTORY")


# ----------------- LEGEND & METADATA -----------------
legend_rect = FancyBboxPatch((4.5, 0.8), 13.0, 0.55,
                             boxstyle="round,pad=0.1,rounding_size=0.15",
                             facecolor="#090D13", edgecolor="#30363D", linewidth=1.0)
ax.add_patch(legend_rect)

# Legend Items
items = [
    (5.0, CYAN, "Client Mobile Use Cases"),
    (8.0, CORAL, "Multi-Engine Detection"),
    (11.0, EMERALD, "Fusion & Explainability"),
    (14.0, AMBER, "Management & Background"),
    (16.5, PURPLE, "External Services")
]
for x, c, label in items:
    patch = patches.Rectangle((x, 0.95), 0.35, 0.22, facecolor=c)
    ax.add_patch(patch)
    plt.text(x + 0.45, 1.06, label, fontsize=8, color=TEXT_WHITE, va="center")

# Output save path
output_path = os.path.abspath("secureshield_use_case_diagram.png")
plt.tight_layout()
plt.savefig(output_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor="none", bbox_inches="tight")
plt.close()

print(f"Successfully generated Use Case diagram at: {output_path}")

