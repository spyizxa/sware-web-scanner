# SwareCommunity - WeB Scanner
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
## 📦 Installation

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


Minimal runtime deps

tkinter 🖼️ – GUI framework (built‑in in many Python distributions)

requests 🌐 – HTTP client

Optional/Recommended

bs4 (BeautifulSoup) 🍲 – HTML parsing for some advanced checks

python-whois 📇 – WHOIS lookups

reportlab 📄 – PDF export

Missing optional packages simply disable related features; the app still works.

🚀 Usage

Launch the app: python sware-web-scanner.py

Enter Target URL (e.g., https://example.com).

Choose Profile:

Quick (Hızlı): common checks + fast vuln probes

Medium (Orta): common + partial recon + vuln tests

Full (Tam): common + full recon + vuln tests

Recon‑only (Sadece Recon): HTTP/SSL/DNS/WHOIS + subdomains/dirs/ports

OWASP Top 10: rule‑based checks mapped to OWASP categories

Click 🚀 Scan. Monitor logs in Console, findings in Results.

Export with 💾 TXT / JSON / 📄 PDF.

🧠 AI Analysis

One‑click summary after a run: prioritized risks, likely root causes, and quick‑win fixes.

Produces a compact executive summary + actionable next steps (EN/TR).
