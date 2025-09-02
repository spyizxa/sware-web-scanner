# SwareCommunity - WeB Scanner
<!-- SVG ikon + kullanıcı adı (responsive) -->
<a href="https://t.me/spyizxa_0day" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:8px;text-decoration:none;color:inherit;">
  <!-- Telegram SVG (küçük, inline) -->
  <svg width="20" height="20" viewBox="0 0 240 240" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <circle cx="120" cy="120" r="120" fill="#2AABEE"/>
    <path d="M50 120l120-48c10-4 18 6 12 15L140 160c-4 6-12 6-16 2L86 132c-4-4-10-2-10 4v22c0 7-6 11-12 8C48 166 50 138 50 120z" fill="#fff"/>
  </svg>
  <span style="font-weight:600;color:#0088cc;">@spyizxa_0day</span>
</a>

Modern, dark‑themed, multi‑threaded desktop web scanner built with Tkinter. It performs fast recon and common vulnerability checks, adds AI‑assisted summaries & prioritization, and exports reports to TXT/JSON/PDF.

# ✨ Features

🌐 Web scanning (HTTP/HTTPS reachability, redirects, headers)

🔒 Security checks: SSL/TLS info, HSTS, CSP, CORS, cookie flags, clickjacking (X‑Frame‑Options)

🕵️ Recon: sensitive paths, robots.txt, directory brute‑force, WAF hints, technology fingerprint

💥 Vulnerability tests: XSS (quick), SQLi (error‑based), LFI, SSTI (basic), IDOR (heuristics), open‑redirect

📡 Networking: DNS/WHOIS, top‑ports probe

📊 Reporting: TXT / JSON / PDF export (PDF via ReportLab)

🤖 AI summary & prioritization (risk score, grouped fixes, quick wins)

🖥️ Console + progress monitor (Notebook tabs)

⚡ Multi‑threaded tasks & selectable profiles (Quick / Medium / Full / Recon‑only / OWASP Top 10)

🌍 UI language: English & Türkçe

# 📦 Installation

```shell
# Clone
git clone https://github.com/spyizxa/sware-web-scanner
cd sware-web-scanner

# (Optional) Create & activate virtualenv
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# Install deps
pip install -r requirements.txt

# Run
python sware-web-scanner.py
```


# Minimal runtime deps

tkinter 🖼️ – GUI framework (built‑in in many Python distributions)

requests 🌐 – HTTP client

Optional/Recommended

bs4 (BeautifulSoup) 🍲 – HTML parsing for some advanced checks

python-whois 📇 – WHOIS lookups

reportlab 📄 – PDF export

Missing optional packages simply disable related features; the app still works.

# 🚀 Usage

Launch the app: python sware-web-scanner.py

Enter Target URL (e.g., https://example.com).

# Choose Profile:

Quick (Hızlı): common checks + fast vuln probes

Medium (Orta): common + partial recon + vuln tests

Full (Tam): common + full recon + vuln tests

Recon‑only (Sadece Recon): HTTP/SSL/DNS/WHOIS + subdomains/dirs/ports

OWASP Top 10: rule‑based checks mapped to OWASP categories

Click 🚀 Scan. Monitor logs in Console, findings in Results.

Export with 💾 TXT / JSON / 📄 PDF.

# 🧠 AI Analysis

One‑click summary after a run: prioritized risks, likely root causes, and quick‑win fixes.

Produces a compact executive summary + actionable next steps (EN/TR).
