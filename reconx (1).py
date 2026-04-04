#!/usr/bin/env python3
"""
ReconX v2.0 — Automated Subdomain & Secret Scanner
For authorized security assessments only.
"""

import argparse
import concurrent.futures
import json
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone

import requests
import urllib3

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "2.0.0"

# ─────────────────────────────────────────────
#  SENSITIVE PATHS  (35+)
# ─────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.env.backup", "/.env.local", "/.env.production",
    "/.env.staging", "/.env.development", "/.env.test",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.svn/wc.db",
    "/config.json", "/config.yml", "/config.yaml",
    "/wp-config.php", "/wp-config.php.bak",
    "/phpinfo.php", "/info.php", "/test.php",
    "/.htpasswd", "/.htaccess",
    "/.aws/credentials", "/.aws/config",
    "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/authorized_keys",
    "/backup.sql", "/dump.sql", "/database.sql",
    "/database.yml", "/database.yaml",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/settings.py", "/local_settings.py",
    "/secrets.yml", "/secrets.yaml", "/secrets.json",
    "/Makefile", "/Dockerfile",
    "/.DS_Store",
    "/server-status", "/server-info",
    "/actuator", "/actuator/env", "/actuator/health",
    "/_profiler/phpinfo",
    "/api/v1/config", "/api/config",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
]

# ─────────────────────────────────────────────
#  SECRET REGEX PATTERNS  (25+)
# ─────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key ID",       r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ("AWS Secret Access Key",   r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
    ("GitHub Token (ghp)",      r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub Token (gho)",      r"gho_[A-Za-z0-9]{36}"),
    ("GitHub Token (ghu)",      r"ghu_[A-Za-z0-9]{36}"),
    ("GitHub Token (ghs)",      r"ghs_[A-Za-z0-9]{36}"),
    ("GitHub Token (ghr)",      r"ghr_[A-Za-z0-9]{36}"),
    ("JSON Web Token",          r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("Google API Key",          r"AIza[A-Za-z0-9\-_]{35}"),
    ("Google OAuth Token",      r"ya29\.[A-Za-z0-9\-_]{40,}"),
    ("Stripe Live Secret Key",  r"sk_live_[A-Za-z0-9]{24,}"),
    ("Stripe Test Secret Key",  r"sk_test_[A-Za-z0-9]{24,}"),
    ("Stripe Publishable Key",  r"pk_(live|test)_[A-Za-z0-9]{24,}"),
    ("Slack OAuth Token",       r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("Slack Webhook",           r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("SendGrid API Key",        r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    ("Mailchimp API Key",       r"[A-Za-z0-9]{32}-us[0-9]{1,2}"),
    ("Twilio Account SID",      r"AC[a-z0-9]{32}"),
    ("Twilio Auth Token",       r"(?i)twilio.{0,20}['\"]([a-z0-9]{32})['\"]"),
    ("PEM Private Key",         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("Generic API Key",         r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"),
    ("Generic Secret Key",      r"(?i)(secret_key|secretkey|secret-key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_!@#$%^&*]{8,})['\"]?"),
    ("Generic Password",        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?"),
    ("Database URL",            r"(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^'\"\s]{8,}"),
    ("Basic Auth in URL",       r"https?://[^/\s:@]{3,}:[^/\s:@]{3,}@[a-zA-Z0-9\.\-]+"),
    ("Bearer Token",            r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}"),
    ("Heroku API Key",          r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("NPM Token",               r"npm_[A-Za-z0-9]{36}"),
    ("PyPI Token",              r"pypi-[A-Za-z0-9\-_]{40,}"),
    ("Cloudflare API Token",    r"(?i)cloudflare.{0,20}['\"]([A-Za-z0-9_\-]{37,})['\"]"),
    ("DigitalOcean Token",      r"dop_v1_[A-Za-z0-9]{64}"),
    ("Telegram Bot Token",      r"[0-9]{8,10}:[A-Za-z0-9\-_]{35}"),
    ("Square Access Token",     r"sq0atp-[A-Za-z0-9\-_]{22}"),
    ("Shopify Token",           r"shpat_[A-Za-z0-9]{32}"),
]

# ─────────────────────────────────────────────
#  COLOUR HELPERS
# ─────────────────────────────────────────────
class C:
    _use = True

    @classmethod
    def disable(cls):
        cls._use = False

    @classmethod
    def _w(cls, code, text):
        if cls._use and HAS_COLOR:
            return f"{code}{text}{Style.RESET_ALL}"
        return text

    @classmethod
    def green(cls, t):  return cls._w(Fore.GREEN,   t)
    @classmethod
    def cyan(cls, t):   return cls._w(Fore.CYAN,    t)
    @classmethod
    def yellow(cls, t): return cls._w(Fore.YELLOW,  t)
    @classmethod
    def red(cls, t):    return cls._w(Fore.RED,     t)
    @classmethod
    def magenta(cls, t):return cls._w(Fore.MAGENTA, t)
    @classmethod
    def dim(cls, t):    return cls._w(Fore.WHITE + Style.DIM, t)
    @classmethod
    def bold(cls, t):   return cls._w(Style.BRIGHT, t)


def info(msg):    print(f"  {C.cyan('[*]')} {msg}")
def ok(msg):      print(f"  {C.green('[+]')} {msg}")
def warn(msg):    print(f"  {C.yellow('[!]')} {msg}")
def err(msg):     print(f"  {C.red('[x]')} {msg}")
def secret(msg):  print(f"  {C.magenta('[SECRET]')} {msg}")
def dim(msg):     print(f"  {C.dim(msg)}")


def progress_bar(current, total, width=40):
    pct = current / total if total else 0
    filled = int(width * pct)
    bar = C.green("█" * filled) + C.dim("░" * (width - filled))
    return f"\r  [{bar}] {int(pct*100):3d}%  ({current}/{total})"


# ─────────────────────────────────────────────
#  MODULE 1 — SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────

def fetch_crtsh(domain: str, timeout: int) -> set:
    """Passive subdomain discovery via crt.sh Certificate Transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
        r.raise_for_status()
        data = r.json()
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
        return subs
    except Exception as exc:
        warn(f"crt.sh error: {exc}")
        return set()


def fetch_wayback(domain: str, timeout: int) -> set:
    """Subdomain discovery via Wayback Machine CDX API."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}&output=text&fl=original&collapse=urlkey&limit=50000"
    )
    subs = set()
    try:
        r = requests.get(url, timeout=timeout * 2)
        r.raise_for_status()
        for line in r.text.splitlines():
            try:
                parsed = urllib.parse.urlparse(line.strip())
                host = parsed.hostname or ""
                host = host.lower().lstrip("*.")
                if host.endswith(f".{domain}") or host == domain:
                    subs.add(host)
            except Exception:
                continue
        return subs
    except Exception as exc:
        warn(f"Wayback error: {exc}")
        return set()


def fetch_otx(domain: str, timeout: int) -> set:
    """Subdomain discovery via AlienVault OTX."""
    subs = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "ReconX/2.0"})
        r.raise_for_status()
        for record in r.json().get("passive_dns", []):
            host = record.get("hostname", "").strip().lower().lstrip("*.")
            if host.endswith(f".{domain}") or host == domain:
                subs.add(host)
        return subs
    except Exception as exc:
        warn(f"OTX error: {exc}")
        return set()


def enumerate_subdomains(domain: str, sources: list, timeout: int) -> list:
    subs = set()
    source_fns = {
        "crtsh":   fetch_crtsh,
        "wayback": fetch_wayback,
        "otx":     fetch_otx,
    }
    for src in sources:
        fn = source_fns.get(src)
        if fn:
            found = fn(domain, timeout)
            subs.update(found)
    return sorted(subs)


# ─────────────────────────────────────────────
#  MODULE 2 — LIVE HOST DETECTION
# ─────────────────────────────────────────────

def get_page_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]{1,120})</title>", html, re.IGNORECASE)
    return m.group(1).strip() if m else ""


def check_host(subdomain: str, timeout: int, verify_ssl: bool) -> dict | None:
    """Probe HTTP/HTTPS with automatic scheme fallback."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}/"
        try:
            r = requests.get(
                url, timeout=timeout,
                verify=verify_ssl,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 ReconX/2.0"},
            )
            title = get_page_title(r.text)
            return {
                "subdomain": subdomain,
                "url": r.url.rstrip("/") + "/",
                "scheme": scheme,
                "status_code": r.status_code,
                "title": title,
                "content_length": len(r.content),
                "path_findings": [],
                "homepage_secrets": [],
            }
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue
    return None


def check_hosts_concurrent(subdomains: list, threads: int,
                            timeout: int, verify_ssl: bool) -> list:
    live = []
    total = len(subdomains)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check_host, s, timeout, verify_ssl): s
                   for s in subdomains}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            print(progress_bar(done, total), end="", flush=True)
            result = fut.result()
            if result:
                live.append(result)
                print()
                ok(f"LIVE  {C.bold(str(result['status_code']))}  "
                   f"{C.cyan(result['url'])}  {C.dim(result['title'])}")
    print()
    return live


# ─────────────────────────────────────────────
#  MODULE 3 — SECRET & PATH SCANNING
# ─────────────────────────────────────────────

def scan_content_for_secrets(content: str, source_url: str) -> list:
    findings = []
    for name, pattern in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            match_str = m.group(0)
            # Truncate long matches for display
            display = match_str[:80] + ("..." if len(match_str) > 80 else "")
            findings.append({
                "url": source_url,
                "pattern_name": name,
                "match": display,
            })
    return findings


def probe_sensitive_path(base_url: str, path: str, timeout: int,
                         verify_ssl: bool, do_secrets: bool) -> dict | None:
    url = base_url.rstrip("/") + path
    try:
        r = requests.get(
            url, timeout=timeout, verify=verify_ssl,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 ReconX/2.0"},
        )
        if r.status_code in (200, 206):
            body = r.text
            secrets = scan_content_for_secrets(body, url) if do_secrets else []
            return {
                "url": url,
                "status_code": r.status_code,
                "content_length": len(r.content),
                "secrets": secrets,
            }
    except Exception:
        pass
    return None


def scan_host(host: dict, timeout: int, verify_ssl: bool,
              do_secrets: bool, do_paths: bool) -> dict:
    base_url = host["url"]

    # Scan homepage for secrets
    if do_secrets:
        try:
            r = requests.get(base_url, timeout=timeout, verify=verify_ssl,
                             headers={"User-Agent": "Mozilla/5.0 ReconX/2.0"})
            host["homepage_secrets"] = scan_content_for_secrets(r.text, base_url)
        except Exception:
            pass

    # Probe sensitive paths
    if do_paths:
        for path in SENSITIVE_PATHS:
            finding = probe_sensitive_path(base_url, path, timeout,
                                           verify_ssl, do_secrets)
            if finding:
                host["path_findings"].append(finding)
                warn(f"Exposed path  {C.cyan(finding['url'])}  "
                     f"({finding['content_length']} bytes)")
                for s in finding["secrets"]:
                    secret(f"{C.bold(s['pattern_name'])} @ "
                           f"{C.cyan(s['url'])} → {C.magenta(s['match'])}")

    return host


def scan_all_hosts(live_hosts: list, threads: int, timeout: int,
                   verify_ssl: bool, do_secrets: bool, do_paths: bool) -> list:
    results = []
    total = len(live_hosts)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_host, h, timeout, verify_ssl,
                               do_secrets, do_paths): h
                   for h in live_hosts}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            print(progress_bar(done, total), end="", flush=True)
            results.append(fut.result())
    print()
    return results


# ─────────────────────────────────────────────
#  MODULE 4 — OUTPUT
# ─────────────────────────────────────────────

def count_totals(results: list) -> tuple:
    paths = sum(len(h["path_findings"]) for h in results)
    secrets = (
        sum(len(h["homepage_secrets"]) for h in results)
        + sum(len(pf["secrets"])
              for h in results
              for pf in h["path_findings"])
    )
    return paths, secrets


def print_summary(subdomains: list, live: list, results: list):
    paths, secrets = count_totals(results)
    sep = C.dim("═" * 56)
    print(f"\n{sep}")
    print(C.bold("  SCAN SUMMARY"))
    print(sep)
    print(f"  Subdomains Found : {C.cyan(str(len(subdomains)))}")
    print(f"  Live Hosts       : {C.green(str(len(live)))}")
    print(f"  Exposed Paths    : {C.yellow(str(paths))}")
    print(f"  Secrets Found    : {C.red(str(secrets))}")
    print(sep)


def save_results(results: list, subdomains: list,
                 output_path: str, domain: str):
    paths, secrets = count_totals(results)
    payload = {
        "tool": "ReconX",
        "version": VERSION,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target": domain,
        "summary": {
            "subdomains_found": len(subdomains),
            "live_hosts": len(results),
            "exposed_paths": paths,
            "secrets_found": secrets,
        },
        "subdomains": subdomains,
        "results": results,
    }

    if output_path.endswith(".json"):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        ok(f"Results saved → {C.cyan(output_path)}")

    elif output_path.endswith(".txt"):
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"ReconX v{VERSION} — Scan Report\n")
            f.write(f"Target  : {domain}\n")
            f.write(f"Time    : {payload['scan_time']}\n")
            f.write("=" * 60 + "\n\n")
            for h in results:
                f.write(f"[{h['status_code']}] {h['url']}  —  {h['title']}\n")
                for pf in h["path_findings"]:
                    f.write(f"  EXPOSED: {pf['url']}  ({pf['content_length']} bytes)\n")
                    for s in pf["secrets"]:
                        f.write(f"    SECRET [{s['pattern_name']}]: {s['match']}\n")
                for s in h["homepage_secrets"]:
                    f.write(f"  HOMEPAGE SECRET [{s['pattern_name']}]: {s['match']}\n")
                f.write("\n")
        ok(f"Report saved → {C.cyan(output_path)}")
    else:
        err(f"Unknown output format for '{output_path}'. Use .json or .txt")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX — Automated Subdomain & Secret Scanner (authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python reconx.py -d example.com\n"
            "  python reconx.py -d example.com -o results.json -t 50\n"
            "  python reconx.py -d example.com --sources crtsh wayback otx\n"
            "  python reconx.py -d example.com --no-secrets --timeout 15\n"
        ),
    )
    p.add_argument("-d", "--domain",   required=True,
                   help="Target domain (e.g. example.com)")
    p.add_argument("-o", "--output",   default=None,
                   help="Save results to file (.json or .txt)")
    p.add_argument("-t", "--threads",  type=int, default=30, metavar="N",
                   help="Concurrent threads (default: 30)")
    p.add_argument("--timeout",        type=int, default=8,  metavar="SECONDS",
                   help="HTTP request timeout in seconds (default: 8)")
    p.add_argument("--sources",        nargs="+",
                   choices=["crtsh", "wayback", "otx"],
                   default=["crtsh"],
                   help="Subdomain sources (default: crtsh)")
    p.add_argument("--no-secrets",     action="store_true",
                   help="Skip secret scanning")
    p.add_argument("--no-paths",       action="store_true",
                   help="Skip sensitive path probing")
    p.add_argument("--no-ssl-verify",  action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("--no-color",       action="store_true",
                   help="Disable colourised output")
    p.add_argument("--version",        action="version",
                   version=f"ReconX {VERSION}")
    return p


BANNER = r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
"""


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.no_color:
        C.disable()

    print(C.green(BANNER))
    print(C.bold(f"  ReconX v{VERSION}") +
          C.dim("  — Automated Subdomain & Secret Scanner"))
    print(C.dim("  For authorized security assessments only.\n"))
    print(C.dim("  ⚠  By proceeding you confirm written permission from the asset owner.\n"))
    print(C.dim("─" * 58))

    domain     = args.domain.strip().lower().lstrip("http://").lstrip("https://").rstrip("/")
    threads    = args.threads
    timeout    = args.timeout
    sources    = args.sources
    do_secrets = not args.no_secrets
    do_paths   = not args.no_paths
    verify_ssl = not args.no_ssl_verify

    # ── Phase 1: Enumeration ──────────────────
    info(f"Enumerating subdomains of {C.cyan(domain)} "
         f"via {C.bold(', '.join(sources))} ...")
    t0 = time.time()
    subdomains = enumerate_subdomains(domain, sources, timeout)
    ok(f"Found {C.bold(str(len(subdomains)))} unique subdomains "
       f"({time.time()-t0:.1f}s)")

    if not subdomains:
        err("No subdomains found. Exiting.")
        sys.exit(1)

    # ── Phase 2: Live Host Detection ──────────
    print()
    info(f"Checking {len(subdomains)} subdomains for live hosts "
         f"({threads} threads, {timeout}s timeout) ...")
    t0 = time.time()
    live_hosts = check_hosts_concurrent(subdomains, threads, timeout, verify_ssl)
    ok(f"Found {C.bold(str(len(live_hosts)))} live hosts "
       f"({time.time()-t0:.1f}s)")

    if not live_hosts:
        err("No live hosts found. Exiting.")
        sys.exit(1)

    # ── Phase 3: Secret & Path Scanning ───────
    if do_secrets or do_paths:
        print()
        mode_str = []
        if do_paths:   mode_str.append("sensitive paths")
        if do_secrets: mode_str.append("secret extraction")
        info(f"Starting {' + '.join(mode_str)} on "
             f"{len(live_hosts)} live hosts ...")
        t0 = time.time()
        results = scan_all_hosts(
            live_hosts, threads, timeout, verify_ssl, do_secrets, do_paths
        )
        ok(f"Scan complete ({time.time()-t0:.1f}s)")
    else:
        results = live_hosts

    # ── Phase 4: Output ───────────────────────
    print_summary(subdomains, live_hosts, results)

    if args.output:
        save_results(results, subdomains, args.output, domain)


if __name__ == "__main__":
    main()
