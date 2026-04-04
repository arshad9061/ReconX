<div align="center">

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**Automated Subdomain & Secret Scanner for Authorized Security Assessments**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00c896?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0.0-blueviolet?style=flat-square)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/arshad9061/reconX/pulls)
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized%20Only-red?style=flat-square)](#-legal-disclaimer)

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is intended exclusively for authorized security testing and educational purposes.**
>
> Scanning domains, networks, or systems **without explicit written permission** from the asset owner is illegal and may violate laws including (but not limited to) the [Computer Fraud and Abuse Act (CFAA)](https://www.law.cornell.edu/uscode/text/18/1030), the [UK Computer Misuse Act](https://www.legislation.gov.uk/ukpga/1990/18/contents), and equivalent legislation in your jurisdiction.
>
> The authors and contributors of ReconX **assume no liability** for misuse of this software. By using ReconX, you confirm that you have obtained all necessary permissions to test the target domain and that you take full legal and ethical responsibility for your actions.
>
> **Always hack responsibly. 🤝**

---

## 📖 What is ReconX?

ReconX is a **modular, multi-threaded reconnaissance tool** built for penetration testers, bug bounty hunters, and security researchers. It automates the early stages of an external assessment by chaining together:

1. 🌐 **Subdomain discovery** — passive enumeration from multiple CT & OSINT sources
2. 🟢 **Live host detection** — HTTP/HTTPS probing with scheme fallback and redirect following
3. 📁 **Sensitive path probing** — 45+ common exposed file paths checked automatically
4. 🔑 **Secret extraction** — 35+ regex patterns targeting real-world credential formats

No external binaries required. No PATH headaches. Pure Python.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 **Multi-Source Enumeration** | crt.sh CT logs · Wayback Machine CDX · AlienVault OTX |
| 🟢 **Live Host Detection** | HTTPS → HTTP fallback, redirect following, title extraction |
| 📁 **Sensitive Path Probing** | 45+ paths — `.env`, `.git/config`, `wp-config.php`, actuator endpoints & more |
| 🔑 **Secret Extraction** | 35+ regex patterns — AWS, JWT, GitHub, Stripe, Slack, DB strings & more |
| 📊 **Live Progress Bar** | Real-time `[████░░] 52%` progress across all scan phases |
| 🚀 **Multi-Threaded** | Concurrent scanning via `concurrent.futures.ThreadPoolExecutor` |
| 🎨 **Colourised Output** | Colour-coded terminal output via `colorama` |
| 💾 **Flexible Reporting** | Structured `.json` with summary block or human-readable `.txt` |
| 🛡️ **Robust Error Handling** | Graceful handling of timeouts, SSL errors, redirects & connection failures |

---

## 🆕 What's New in v2.0

| Feature | v1.0 | v2.0 |
|---|---|---|
| Subdomain sources | crt.sh only | **crt.sh + Wayback Machine + OTX** |
| Secret patterns | 18 | **35+** |
| Sensitive paths | 35+ | **45+** |
| Progress reporting | None | **Live progress bar** |
| JSON output schema | Basic | **Rich schema with summary block** |
| SSL verification | Always on | **`--no-ssl-verify` flag** |
| Source selection | Fixed | **`--sources crtsh wayback otx`** |
| Path scanning toggle | None | **`--no-paths` flag** |
| Token types | Common only | **+ NPM, PyPI, Shopify, DigitalOcean, Cloudflare, Telegram, Square** |

---

## 🔍 What ReconX Scans For

<details>
<summary><strong>📁 Sensitive Paths (45+)</strong></summary>

```
/.env                /.env.backup         /.env.local
/.env.production     /.env.staging        /.env.development
/.git/config         /.git/HEAD           /.git/COMMIT_EDITMSG
/.svn/entries        /.svn/wc.db
/config.json         /config.yml          /config.yaml
/wp-config.php       /wp-config.php.bak
/phpinfo.php         /info.php            /test.php
/.htpasswd           /.htaccess
/.aws/credentials    /.aws/config
/.ssh/id_rsa         /.ssh/id_ed25519     /.ssh/authorized_keys
/backup.sql          /dump.sql            /database.sql
/database.yml        /docker-compose.yml
/settings.py         /local_settings.py
/secrets.yml         /secrets.json
/Makefile            /Dockerfile          /.DS_Store
/server-status       /server-info
/actuator            /actuator/env        /actuator/health
/_profiler/phpinfo
/api/v1/config       /api/config
/robots.txt          /sitemap.xml
/crossdomain.xml     /clientaccesspolicy.xml
```

</details>

<details>
<summary><strong>🔑 Secret Patterns (35+)</strong></summary>

| Category | Patterns |
|---|---|
| **AWS** | Access Key ID (`AKIA…`), Secret Access Key |
| **GitHub** | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens |
| **Google** | API Key (`AIza…`), OAuth Token (`ya29…`) |
| **Stripe** | Live/Test Secret Keys, Publishable Keys |
| **Slack** | OAuth Tokens (`xox…`), Incoming Webhooks |
| **Auth Tokens** | JWT, Bearer tokens, Basic Auth in URLs |
| **Email APIs** | SendGrid, Mailchimp, Twilio |
| **Cloud** | Heroku, Cloudflare, DigitalOcean (`dop_v1_…`) |
| **Package Registries** | NPM (`npm_…`), PyPI (`pypi-…`) |
| **E-Commerce** | Shopify (`shpat_…`), Square (`sq0atp-…`) |
| **Messaging** | Telegram Bot Token |
| **Crypto** | PEM Private Keys (RSA, EC, DSA, OpenSSH) |
| **Databases** | MySQL, Postgres, MongoDB, Redis, AMQP connection strings |
| **Generic** | `API_KEY`, `SECRET_KEY`, `PASSWORD` patterns |

</details>

---

## 📋 Requirements

- **Python 3.10+**
- pip packages: `requests`, `colorama`, `urllib3`

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/arshad9061/reconX.git
cd reconx

# 2. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🖥️ Usage

### Minimal — basic scan with crt.sh
```bash
python reconx.py -d example.com
```

### Maximum coverage — all sources, save as JSON
```bash
python reconx.py -d example.com --sources crtsh wayback otx -o results.json
```

### Fast recon — 50 threads, skip secret scanning
```bash
python reconx.py -d example.com -t 50 --no-secrets
```

### Subdomain + live check only — no path or secret scanning
```bash
python reconx.py -d example.com --no-secrets --no-paths
```

### Save a human-readable plain-text report
```bash
python reconx.py -d example.com -o report.txt
```

### Behind a proxy / self-signed cert environment
```bash
python reconx.py -d example.com --no-ssl-verify
```

### Full-power scan with all options
```bash
python reconx.py -d example.com \
  --sources crtsh wayback otx \
  -t 40 \
  --timeout 10 \
  --no-ssl-verify \
  -o results.json
```

### Pipe to log file (disable colour)
```bash
python reconx.py -d example.com --no-color | tee scan.log
```

---

## 📚 CLI Reference

```
usage: reconx [-h] -d DOMAIN [-o OUTPUT] [-t N] [--timeout SECONDS]
              [--sources {crtsh,wayback,otx} [...]]
              [--no-secrets] [--no-paths] [--no-ssl-verify]
              [--no-color] [--version]

options:
  -h, --help                        Show this help message and exit
  -d, --domain DOMAIN               Target domain (e.g. example.com)
  -o, --output OUTPUT               Save results to file (.json or .txt)
  -t, --threads N                   Concurrent threads (default: 30)
  --timeout SECONDS                 HTTP request timeout in seconds (default: 8)
  --sources {crtsh,wayback,otx}     Subdomain sources — one or more (default: crtsh)
  --no-secrets                      Skip secret scanning
  --no-paths                        Skip sensitive path probing
  --no-ssl-verify                   Disable SSL certificate verification
  --no-color                        Disable colourised output
  --version                         Show version number and exit
```

---

## 📤 Sample Terminal Output

```
  ReconX v2.0.0  — Automated Subdomain & Secret Scanner
  For authorized security assessments only.

  ⚠  By proceeding you confirm written permission from the asset owner.

  [*] Enumerating subdomains of example.com via crtsh, wayback, otx ...
  [+] Found 47 unique subdomains (3.2s)

  [*] Checking 47 subdomains for live hosts (30 threads, 8s timeout) ...
  [████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░]  30%  (14/47)
  [+] LIVE  200  https://api.example.com/         API Gateway
  [+] LIVE  200  https://mail.example.com/        Webmail Login
  [+] LIVE  301  https://dev.example.com/         Dev Portal
  [+] Found 12 live hosts (18.4s)

  [*] Starting sensitive paths + secret extraction on 12 live hosts ...
  [████████████████████████████████████████] 100%  (12/12)
  [!] Exposed path  https://dev.example.com/.env  (1842 bytes)
  [SECRET] AWS Access Key ID @ https://dev.example.com/.env → AKIAIOSFODNN7EXAMPLE
  [SECRET] Generic Password  @ https://dev.example.com/.env → DB_PASSWORD=s3cr3t!

  ════════════════════════════════════════════════════════
    SCAN SUMMARY
  ════════════════════════════════════════════════════════
    Subdomains Found :  47
    Live Hosts       :  12
    Exposed Paths    :   3
    Secrets Found    :   5
  ════════════════════════════════════════════════════════

  [+] Results saved → results.json
```

---

## 🗂️ JSON Output Schema

```json
{
  "tool": "ReconX",
  "version": "2.0.0",
  "scan_time": "2025-08-01T14:32:00+00:00",
  "target": "example.com",
  "summary": {
    "subdomains_found": 47,
    "live_hosts": 12,
    "exposed_paths": 3,
    "secrets_found": 5
  },
  "subdomains": [
    "api.example.com",
    "dev.example.com"
  ],
  "results": [
    {
      "subdomain": "dev.example.com",
      "url": "https://dev.example.com/",
      "scheme": "https",
      "status_code": 200,
      "title": "Dev Portal",
      "content_length": 4821,
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
├── reconx.py          # Main scanner — all modules in one file
├── requirements.txt   # Python dependencies
├── README.md          # This file
└── LICENSE            # MIT License
```

### Code Modules (inside `reconx.py`)

| Module | Functions | Description |
|---|---|---|
| **1 — Enumeration** | `fetch_crtsh()` `fetch_wayback()` `fetch_otx()` `enumerate_subdomains()` | Multi-source passive subdomain discovery |
| **2 — Live Check** | `check_host()` `check_hosts_concurrent()` | Multi-threaded HTTP/HTTPS probing with title extraction |
| **3 — Scanning** | `probe_sensitive_path()` `scan_content_for_secrets()` `scan_all_hosts()` | Path probing + regex secret extraction |
| **4 — Output** | `print_summary()` `save_results()` | Terminal display, JSON & TXT reporting |
| **CLI** | `build_arg_parser()` `main()` | Argument parsing and orchestration |

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch — `git checkout -b feature/new-pattern`
3. Commit your changes with clear messages
4. Open a Pull Request

**Ideas for contributions:**

- [ ] Additional secret regex patterns
- [ ] More sensitive path entries
- [ ] DNS brute-force module
- [ ] Shodan / Censys integration
- [ ] Slack / Discord webhook notifications
- [ ] HTML report output format
- [ ] Rate limiting / throttle control
- [ ] Resume scan from checkpoint

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with ❤️ for the security community &nbsp;·&nbsp; [Report Issues](https://github.com/arshad9061/reconX/issues) &nbsp;·&nbsp; [Pull Requests](https://github.com/arshad9061/reconX/pulls)

</div>
