# ReconX 🔍

> **Automated Subdomain & Secret Scanner for Authorized Security Assessments**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

---

## ⚠️ Legal Disclaimer

> **This tool is intended exclusively for authorized security testing and educational purposes.**
>
> Scanning domains, networks, or systems **without explicit written permission** from the asset owner is **illegal** and may violate laws including (but not limited to) the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation in your jurisdiction.
>
> **The authors and contributors of ReconX assume no liability** for misuse of this software. By using ReconX, you confirm that you have obtained all necessary permissions to test the target domain and that you take full legal and ethical responsibility for your actions.
>
> **Always hack responsibly.**

---

## 📖 Description

ReconX is a modular, multi-threaded reconnaissance tool designed for penetration testers, bug bounty hunters, and security researchers. It automates the early stages of an external assessment by chaining subdomain discovery, live host validation, and secret/credential scanning into a single, zero-dependency-binary workflow.

Unlike tools that rely on external binaries like `amass` or `subfinder`, ReconX runs entirely in Python using the [crt.sh](https://crt.sh) Certificate Transparency API — no setup headaches, no PATH issues.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 **Subdomain Enumeration** | Passively queries crt.sh Certificate Transparency logs |
| 🟢 **Live Host Detection** | HTTP/HTTPS probing with automatic scheme fallback and redirect following |
| 📁 **Sensitive Path Probing** | Checks 35+ common exposed file paths (`.env`, `.git/config`, `wp-config.php`, etc.) |
| 🔑 **Secret Extraction** | 18 regex patterns targeting AWS keys, JWTs, GitHub tokens, Stripe keys, and more |
| 🚀 **Multi-Threaded** | Concurrent scanning via `concurrent.futures.ThreadPoolExecutor` |
| 🎨 **Colorised Output** | Clear, colour-coded terminal output via `colorama` |
| 💾 **Flexible Reporting** | Save results as structured `.json` or human-readable `.txt` |
| 🛡️ **Robust Error Handling** | Graceful handling of timeouts, SSL errors, redirects, and connection failures |

---

## 🔍 What ReconX Scans For

### Sensitive Paths
```
/.env             /.env.backup       /.git/config      /.git/HEAD
/.svn/entries     /config.json       /wp-config.php    /phpinfo.php
/.htpasswd        /.aws/credentials  /.ssh/id_rsa      /backup.sql
/database.yml     /docker-compose.yml                  /settings.py
... and 20+ more
```

### Secret Patterns (Regex)
- AWS Access Key IDs & Secret Access Keys
- GitHub Personal Access Tokens (`ghp_`, `gho_`, etc.)
- JSON Web Tokens (JWT)
- Google API Keys
- Stripe Live/Test Secret Keys
- Slack OAuth Tokens
- SendGrid, Mailchimp, Twilio API Keys
- PEM Private Keys
- Generic `API_KEY`, `SECRET_KEY`, `PASSWORD` patterns
- Database connection strings (MySQL, Postgres, MongoDB, Redis)
- Basic Auth credentials in URLs
- Bearer tokens

---

## 📋 Requirements

- Python **3.10+**
- pip packages: `requests`, `colorama`, `urllib3`

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/arshad9061/reconx.git
cd reconx

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🖥️ Usage

### Basic Scan
```bash
python reconx.py -d example.com
```

### Save Results as JSON
```bash
python reconx.py -d example.com -o results.json
```

### Save Results as Plain Text
```bash
python reconx.py -d example.com -o report.txt
```

### Increase Threads for Faster Scanning
```bash
python reconx.py -d example.com -t 50
```

### Set a Custom Request Timeout
```bash
python reconx.py -d example.com --timeout 15
```

### Subdomain + Live Host Enumeration Only (Skip Secret Scanning)
```bash
python reconx.py -d example.com --no-secrets
```

### Disable Colour Output (for log files / piping)
```bash
python reconx.py -d example.com --no-color | tee scan.log
```

### Full Example with All Options
```bash
python reconx.py -d example.com -o results.json -t 40 --timeout 10
```

---

## 📚 CLI Reference

```
usage: reconx [-h] -d DOMAIN [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT]
              [--no-secrets] [--no-color] [--version]

options:
  -h, --help            Show this help message and exit
  -d, --domain DOMAIN   Target domain to enumerate (e.g. example.com)
  -o, --output OUTPUT   Save results to file (.json or .txt)
  -t, --threads N       Number of concurrent threads (default: 30)
  --timeout SECONDS     HTTP request timeout in seconds (default: 8)
  --no-secrets          Skip secret scanning; enumerate and check hosts only
  --no-color            Disable colorised output
  --version             Show version number and exit
```

---

## 📤 Sample Output

```
[*] Querying crt.sh for subdomains of example.com ...
[+] crt.sh returned 47 unique subdomains.

[*] Checking 47 subdomains for live hosts (30 threads, 8s timeout) ...
[+] LIVE  200  https://api.example.com          API Gateway
[+] LIVE  200  https://mail.example.com         Webmail Login
[+] LIVE  301  https://dev.example.com          Development Portal
[+] Found 12 live hosts.

[*] Starting secret scan on 12 live hosts ...
[!] Exposed path  https://dev.example.com/.env  (1842 bytes)
[SECRET] AWS Access Key ID @ https://dev.example.com/.env → AKIA...EXAMPLE
[SECRET] Generic Secret @ https://dev.example.com/.env → DB_PASSWORD=s3cr3t

════════════════════════════════════════════════════════════
  SCAN SUMMARY
════════════════════════════════════════════════════════════
  Live Hosts:        12
  Exposed Paths:     3
  Secrets Found:     5
════════════════════════════════════════════════════════════
```

---

## 🗂️ JSON Output Format

```json
{
  "scan_time": "2025-08-01T14:32:00Z",
  "results": [
    {
      "subdomain": "dev.example.com",
      "url": "https://dev.example.com/",
      "scheme": "https",
      "status_code": 200,
      "title": "Development Portal",
      "path_findings": [
        {
          "url": "https://dev.example.com/.env",
          "status_code": 200,
          "content_length": 1842,
          "secrets": [
            {
              "url": "https://dev.example.com/.env",
              "pattern_name": "AWS Access Key ID",
              "match": "AKIAIOSFODNN7EXAMPLE"
            }
          ]
        }
      ],
      "homepage_secrets": []
    }
  ]
}
```

---

## 🏗️ Project Structure

```
reconx/
├── reconx.py          # Main scanner script (all modules)
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

### Code Modules (inside `reconx.py`)

| Module | Function(s) | Description |
|---|---|---|
| 1 — Enumeration | `fetch_subdomains_crtsh()` | Passive subdomain discovery via crt.sh |
| 2 — Live Check | `check_host()`, `check_hosts_concurrent()` | Multi-threaded HTTP/HTTPS probing |
| 3 — Scanning | `probe_sensitive_path()`, `scan_url_for_secrets()`, `scan_all_hosts()` | Path probing + regex secret extraction |
| 4 — Output | `print_summary()`, `save_results()` | Terminal display and file reporting |
| CLI | `build_arg_parser()`, `main()` | Argument parsing and orchestration |

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-pattern`)
3. Commit your changes with clear messages
4. Open a Pull Request

Ideas for contributions:
- Additional secret regex patterns
- More sensitive path entries
- DNS brute-force module
- Wayback Machine / AlienVault OTX subdomain sources
- Shodan/Censys integration
- Slack/Discord webhook notifications

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Responsible Disclosure

If you discover a real vulnerability using ReconX, please follow **responsible disclosure** practices:

1. Do **not** publicly disclose the vulnerability before notifying the affected party.
2. Report findings privately to the organization's security team or via their bug bounty program (e.g., HackerOne, Bugcrowd).
3. Allow a reasonable remediation window (typically 90 days) before any public disclosure.

---

*Built for the security community, with ❤️ and a healthy respect for the rules of engagement.*
