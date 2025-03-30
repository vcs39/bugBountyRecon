readme_content = """# 🕵️‍♂️ Bug Bounty Recon Automation

![Python](https://img.shields.io/badge/Made%20with-Python-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

## 🔐 Vicious Cyber Solutions Presents

A fully automated bug bounty recon script for OSINT-driven reconnaissance and vulnerability discovery. Perfect for bounty hunters, pentesters, and students looking to streamline their web application recon workflow.

---

## 📜 Features

- 🎯 Wildcard Subdomain Enumeration
- 🧪 Live Subdomain Probing
- 📸 Screenshots with Aquatone
- 🔍 Nmap Full Port Scanning
- 🕸️ JS/Param Discovery (`linkfinder`, `paramspider`)
- 📂 Directory Brute Force (`ffuf`)
- 🔎 Tech Stack Fingerprinting (`whatweb`)
- 🧾 SSL & Service Analysis
- 🗃️ HTML Report Generation
- 💡 Google Dork Suggestions

---

## ⚙️ Requirements

Install these tools and ensure they are in your `PATH`:

- [`amass`](https://github.com/owasp-amass/amass)
- [`subfinder`](https://github.com/projectdiscovery/subfinder)
- [`assetfinder`](https://github.com/tomnomnom/assetfinder)
- [`httprobe`](https://github.com/tomnomnom/httprobe)
- [`aquatone`](https://github.com/michenriksen/aquatone)
- [`nmap`](https://nmap.org)
- [`ffuf`](https://github.com/ffuf/ffuf)
- [`hakrawler`](https://github.com/hakluke/hakrawler)
- [`paramspider`](https://github.com/devanshbatham/paramspider)
- [`whatweb`](https://github.com/urbanadventurer/WhatWeb)
- [`sslscan`](https://github.com/rbsec/sslscan)
- [`LinkFinder`](https://github.com/GerbenJavado/LinkFinder)

---

## 🧪 Installation

```bash
git clone https://github.com/yourusername/bugbounty-recon.git
cd bugbounty-recon
python3 -m venv .venv
source .venv/bin/activate  # or .venv\\Scripts\\activate on Windows
pip install -r requirements.txt


Default domain (if none provided): testphp.vulnweb.com


All results are saved in:

bugbounty_output/YYYYMMDD_HHMMSS/
Includes:

Enumerated subdomains

Live domains

Screenshots

Scanned ports

JS endpoints

Params

Directory brute results

HTML recon report

📸 Preview
Screenshot and recon summary results displayed in an HTML report format.

📄 License
MIT License

💬 Credits
Maintained by Vicious Cyber Solutions
ASCII Art by Robert
Inspired by OSINT & bug bounty best practices ""



