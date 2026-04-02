#!/usr/bin/env python3
"""
ReconX - Automated Subdomain & Secret Scanner
=============================================
A modular, multi-threaded reconnaissance tool for authorized security assessments.

Author: ReconX Contributors
License: MIT
Disclaimer: For authorized testing only. You are responsible for compliance
            with all applicable laws and obtaining proper permissions.
"""

import re
import json
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
import urllib3
from colorama import Fore, Style, init

# ── Init colorama (auto-reset after each print) ────────────────────────────────
init(autoreset=True)

# Suppress InsecureRequestWarning for hosts with bad certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"

BANNER = rf"""
{Fore.CYAN}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}  Automated Subdomain & Secret Scanner  v{VERSION}{Style.RESET_ALL}
{Fore.RED}  [ For authorized testing only ]{Style.RESET_ALL}
"""

# Sensitive paths to probe on each live host
SENSITIVE_PATHS = [
    "/.env",
    "/.env.backup",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.svn/wc.db",
    "/config.php",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/debug.log",
    "/error.log",
    "/app.log",
    "/server.log",
    "/.htpasswd",
    "/web.config",
    "/credentials.json",
    "/secrets.json",
    "/api_keys.txt",
    "/database.yml",
    "/settings.py",
    "/local_settings.py",
    "/docker-compose.yml",
    "/Dockerfile",
    "/.dockerenv",
    "/backup.sql",
    "/dump.sql",
    "/db.sqlite3",
    "/.bash_history",
    "/.ssh/id_rsa",
    "/.aws/credentials",
    "/robots.txt",       # Not sensitive, but useful recon
    "/sitemap.xml",
]

# Regex patterns for secret detection
SECRET_PATTERNS = {
    "AWS Access Key ID":        r"(?<![A-Z0-9])(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])",
    "AWS Secret Access Key":    r"(?i)aws.{0,30}secret.{0,30}['\"]([A-Za-z0-9/+=]{40})['\"]",
    "Generic API Key":          r"(?i)(api[_\-\s]?key|apikey)['\"\s:=]+([A-Za-z0-9\-_]{20,64})",
    "Generic Secret":           r"(?i)(secret[_\-\s]?key|client[_\-\s]?secret)['\"\s:=]+([A-Za-z0-9\-_]{16,64})",
    "JWT Token":                r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "GitHub Token":             r"(?i)gh[pousr]_[A-Za-z0-9_]{36,255}",
    "Slack Token":              r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}",
    "Stripe Secret Key":        r"sk_(live|test)_[A-Za-z0-9]{24,}",
    "Google API Key":           r"AIza[A-Za-z0-9\-_]{35}",
    "Private Key (PEM)":        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Basic Auth in URL":        r"https?://[^:@\s]+:[^:@\s]+@[^/\s]+",
    "Password in Config":       r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{6,})['\"]?",
    "Database Connection Str":  r"(?i)(mysql|postgres|mongodb|redis)://[^\s'\"]+",
    "Bearer Token":             r"(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})",
    "SendGrid API Key":         r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "Mailchimp API Key":        r"[A-Za-z0-9]{32}-us[0-9]{1,2}",
    "Twilio Account SID":       r"AC[a-z0-9]{32}",
    "Twilio Auth Token":        r"(?i)twilio.{0,20}['\"]([a-z0-9]{32})['\"]",
}

DEFAULT_TIMEOUT = 8       # seconds per HTTP request
DEFAULT_THREADS = 30      # concurrent threads
MAX_RESPONSE_BYTES = 512_000  # 512 KB max body to scan


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def log_info(msg: str) -> None:
    """Print a standard informational message."""
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")


def log_success(msg: str) -> None:
    """Print a success / found message."""
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def log_warn(msg: str) -> None:
    """Print a warning message."""
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def log_error(msg: str) -> None:
    """Print an error message."""
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def log_secret(label: str, url: str, snippet: str) -> None:
    """Print a highlighted secret finding."""
    print(
        f"{Fore.RED}{Style.BRIGHT}[SECRET]{Style.RESET_ALL} "
        f"{Fore.YELLOW}{label}{Style.RESET_ALL} "
        f"@ {Fore.CYAN}{url}{Style.RESET_ALL} "
        f"→ {Fore.WHITE}{snippet[:120]}{Style.RESET_ALL}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════════════════════

def fetch_subdomains_crtsh(domain: str, timeout: int = DEFAULT_TIMEOUT) -> set[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains of *domain*.

    Returns a deduplicated set of subdomain strings (lowercased).
    Raises no exceptions — failures are logged and an empty set is returned.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    log_info(f"Querying crt.sh for subdomains of {Fore.CYAN}{domain}{Style.RESET_ALL} ...")

    try:
        resp = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
        resp.raise_for_status()
        entries = resp.json()
    except requests.exceptions.Timeout:
        log_error("crt.sh request timed out.")
        return set()
    except requests.exceptions.RequestException as exc:
        log_error(f"crt.sh request failed: {exc}")
        return set()
    except ValueError:
        log_error("crt.sh returned non-JSON data.")
        return set()

    subdomains: set[str] = set()
    for entry in entries:
        # name_value may contain newline-separated entries or wildcards
        name_value = entry.get("name_value", "")
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            # Keep only names that belong to the target domain
            if name.endswith(f".{domain}") or name == domain:
                subdomains.add(name)

    log_success(f"crt.sh returned {Fore.GREEN}{len(subdomains)}{Style.RESET_ALL} unique subdomains.")
    return subdomains


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — LIVE HOST CHECKING
# ══════════════════════════════════════════════════════════════════════════════

def check_host(subdomain: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[dict]:
    """
    Check whether a subdomain resolves and serves HTTP(S).

    Tries HTTPS first, then HTTP. Returns a dict with host details on success,
    or None if the host is unreachable.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                verify=False,           # Accept self-signed certs
                allow_redirects=True,
                headers={"User-Agent": "ReconX/1.0 (Security Scanner)"},
            )
            return {
                "subdomain": subdomain,
                "url": resp.url,          # Final URL after redirects
                "scheme": scheme,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "server": resp.headers.get("Server", ""),
                "title": _extract_title(resp.text),
            }
        except requests.exceptions.SSLError:
            # SSL error on https → try http next iteration
            continue
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects,
        ):
            break   # Host is down or unreachable — skip http fallback too
        except requests.exceptions.RequestException:
            break

    return None


def _extract_title(html: str) -> str:
    """Extract the <title> tag value from an HTML string."""
    match = re.search(r"<title[^>]*>([^<]{0,200})</title>", html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def check_hosts_concurrent(
    subdomains: set[str],
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """
    Run check_host() concurrently across all *subdomains*.

    Returns a list of host-info dicts for every live host found.
    """
    log_info(f"Checking {len(subdomains)} subdomains for live hosts "
             f"({threads} threads, {timeout}s timeout) ...")

    live_hosts: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_host, sd, timeout): sd for sd in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                status_color = Fore.GREEN if result["status_code"] < 400 else Fore.YELLOW
                log_success(
                    f"LIVE  {status_color}{result['status_code']}{Style.RESET_ALL}  "
                    f"{Fore.CYAN}{result['url']}{Style.RESET_ALL}  "
                    f"{Fore.WHITE}{result['title'][:60]}{Style.RESET_ALL}"
                )
                live_hosts.append(result)

    log_success(f"Found {Fore.GREEN}{len(live_hosts)}{Style.RESET_ALL} live hosts.")
    return live_hosts


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — SECRET SCANNING
# ══════════════════════════════════════════════════════════════════════════════

def scan_url_for_secrets(url: str, content: str) -> list[dict]:
    """
    Run all SECRET_PATTERNS against *content*.

    Returns a list of finding dicts:
        { "url": str, "pattern_name": str, "match": str }
    """
    findings: list[dict] = []
    for pattern_name, regex in SECRET_PATTERNS.items():
        matches = re.findall(regex, content)
        for match in matches:
            # re.findall returns strings or tuples depending on groups
            value = match if isinstance(match, str) else " | ".join(match)
            findings.append({
                "url": url,
                "pattern_name": pattern_name,
                "match": value[:200],   # Truncate for safety / readability
            })
    return findings


def probe_sensitive_path(
    base_url: str,
    path: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Optional[dict]:
    """
    Request *base_url* + *path* and return a result dict if status is 200.

    Returns None for non-200 responses or on any request error.
    """
    url = base_url.rstrip("/") + path
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=False,      # Don't follow redirects for sensitive files
            headers={"User-Agent": "ReconX/1.0 (Security Scanner)"},
            stream=True,                # Avoid downloading huge files
        )
        if resp.status_code == 200:
            # Read up to MAX_RESPONSE_BYTES to avoid memory issues
            content = resp.raw.read(MAX_RESPONSE_BYTES, decode_content=True).decode(
                "utf-8", errors="replace"
            )
            secrets = scan_url_for_secrets(url, content)
            return {
                "url": url,
                "status_code": resp.status_code,
                "content_length": len(content),
                "content_type": resp.headers.get("Content-Type", ""),
                "secrets": secrets,
                "snippet": content[:300],
            }
    except (requests.exceptions.RequestException, UnicodeDecodeError):
        pass
    return None


def scan_homepage_for_secrets(host_info: dict, timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """
    Fetch the homepage of a live host and scan its source for secrets.

    Returns a list of finding dicts (may be empty).
    """
    url = host_info["url"]
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "ReconX/1.0 (Security Scanner)"},
            stream=True,
        )
        content = resp.raw.read(MAX_RESPONSE_BYTES, decode_content=True).decode(
            "utf-8", errors="replace"
        )
        return scan_url_for_secrets(url, content)
    except requests.exceptions.RequestException:
        return []


def scan_host(
    host_info: dict,
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    Perform full secret scanning on a single live host:
      1. Probe all SENSITIVE_PATHS concurrently.
      2. Scan the homepage source code.

    Returns an enriched host_info dict with 'path_findings' and 'homepage_secrets'.
    """
    base_url = f"{host_info['scheme']}://{host_info['subdomain']}"
    path_findings: list[dict] = []
    homepage_secrets: list[dict] = []

    # ── Probe sensitive paths ──────────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=min(threads, 20)) as executor:
        futures = {
            executor.submit(probe_sensitive_path, base_url, path, timeout): path
            for path in SENSITIVE_PATHS
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                log_warn(
                    f"Exposed path  {Fore.YELLOW}{result['url']}{Style.RESET_ALL}  "
                    f"({result['content_length']} bytes)"
                )
                if result["secrets"]:
                    for s in result["secrets"]:
                        log_secret(s["pattern_name"], s["url"], s["match"])
                path_findings.append(result)

    # ── Scan homepage ──────────────────────────────────────────────────────
    homepage_secrets = scan_homepage_for_secrets(host_info, timeout)
    for s in homepage_secrets:
        log_secret(s["pattern_name"], s["url"], s["match"])

    return {
        **host_info,
        "path_findings": path_findings,
        "homepage_secrets": homepage_secrets,
    }


def scan_all_hosts(
    live_hosts: list[dict],
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """
    Run scan_host() for every host in *live_hosts* concurrently (host-level
    parallelism; each host also uses internal threading for path probing).
    """
    log_info(f"Starting secret scan on {len(live_hosts)} live hosts ...")
    results: list[dict] = []

    # Use a moderate host-level concurrency to avoid overwhelming path threads
    host_threads = max(1, min(threads // 5, len(live_hosts), 10))
    with ThreadPoolExecutor(max_workers=host_threads) as executor:
        futures = {
            executor.submit(scan_host, host, threads, timeout): host["subdomain"]
            for host in live_hosts
        }
        for future in as_completed(futures):
            results.append(future.result())

    return results


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — OUTPUT / REPORTING
# ══════════════════════════════════════════════════════════════════════════════

def print_summary(results: list[dict]) -> None:
    """Print a colourised summary table to stdout."""
    total_paths = sum(len(r.get("path_findings", [])) for r in results)
    total_secrets = sum(
        len(r.get("homepage_secrets", []))
        + sum(len(pf.get("secrets", [])) for pf in r.get("path_findings", []))
        for r in results
    )

    print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    print(f"  Live Hosts:        {Fore.GREEN}{len(results)}{Style.RESET_ALL}")
    print(f"  Exposed Paths:     {Fore.YELLOW}{total_paths}{Style.RESET_ALL}")
    print(f"  Secrets Found:     {Fore.RED}{total_secrets}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")

    for r in results:
        host_secrets = len(r.get("homepage_secrets", [])) + sum(
            len(pf.get("secrets", [])) for pf in r.get("path_findings", [])
        )
        color = Fore.RED if host_secrets else (Fore.YELLOW if r.get("path_findings") else Fore.GREEN)
        print(
            f"  {color}{r['subdomain']:<45}{Style.RESET_ALL} "
            f"paths={len(r.get('path_findings', []))}  "
            f"secrets={host_secrets}"
        )


def save_results(results: list[dict], output_path: str) -> None:
    """
    Persist scan results to *output_path*.

    The format is inferred from the file extension:
      .json → pretty-printed JSON
      anything else → plain-text report
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.suffix.lower() == ".json":
        with path.open("w", encoding="utf-8") as fh:
            json.dump(
                {
                    "scan_time": datetime.utcnow().isoformat() + "Z",
                    "results": results,
                },
                fh,
                indent=2,
                default=str,
            )
        log_success(f"Results saved to {Fore.CYAN}{path}{Style.RESET_ALL} (JSON)")
    else:
        with path.open("w", encoding="utf-8") as fh:
            fh.write(f"ReconX Scan Report — {datetime.utcnow().isoformat()}Z\n")
            fh.write("=" * 70 + "\n\n")
            for r in results:
                fh.write(f"Host: {r['subdomain']}\n")
                fh.write(f"  URL:    {r.get('url', '')}\n")
                fh.write(f"  Status: {r.get('status_code', '')}\n")
                fh.write(f"  Title:  {r.get('title', '')}\n")
                if r.get("path_findings"):
                    fh.write("  Exposed Paths:\n")
                    for pf in r["path_findings"]:
                        fh.write(f"    - {pf['url']} ({pf['content_length']} bytes)\n")
                        for s in pf.get("secrets", []):
                            fh.write(f"      [SECRET] {s['pattern_name']}: {s['match'][:100]}\n")
                if r.get("homepage_secrets"):
                    fh.write("  Homepage Secrets:\n")
                    for s in r["homepage_secrets"]:
                        fh.write(f"    [SECRET] {s['pattern_name']}: {s['match'][:100]}\n")
                fh.write("\n")
        log_success(f"Results saved to {Fore.CYAN}{path}{Style.RESET_ALL} (TXT)")


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRYPOINT
# ══════════════════════════════════════════════════════════════════════════════

def build_arg_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="reconx",
        description=(
            "ReconX — Automated Subdomain & Secret Scanner\n"
            "For authorized penetration testing and security research only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python reconx.py -d example.com\n"
            "  python reconx.py -d example.com -o results.json -t 50\n"
            "  python reconx.py -d example.com --timeout 15 --no-secrets\n"
        ),
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain to enumerate (e.g. example.com)",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Save results to file (.json or .txt). Default: no file output.",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--no-secrets",
        action="store_true",
        help="Skip secret scanning; only enumerate subdomains and check live hosts.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colorised output (useful for piping / log files).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ReconX {VERSION}",
    )
    return parser


def main() -> None:
    """Main orchestration function."""
    parser = build_arg_parser()
    args = parser.parse_args()

    # Disable colour if requested
    if args.no_color:
        init(strip=True, autoreset=True)

    print(BANNER)

    domain = args.domain.lower().strip().lstrip("www.").rstrip("/")
    start_time = time.time()

    log_info(f"Target domain  : {Fore.CYAN}{domain}{Style.RESET_ALL}")
    log_info(f"Threads        : {args.threads}")
    log_info(f"Timeout        : {args.timeout}s")
    log_info(f"Secret scan    : {'disabled' if args.no_secrets else 'enabled'}")
    if args.output:
        log_info(f"Output file    : {args.output}")
    print()

    # ── Step 1: Subdomain enumeration ─────────────────────────────────────
    subdomains = fetch_subdomains_crtsh(domain, timeout=args.timeout)
    if not subdomains:
        log_warn("No subdomains discovered. Exiting.")
        sys.exit(0)

    # ── Step 2: Live host checking ─────────────────────────────────────────
    print()
    live_hosts = check_hosts_concurrent(subdomains, threads=args.threads, timeout=args.timeout)
    if not live_hosts:
        log_warn("No live hosts found. Exiting.")
        sys.exit(0)

    # ── Step 3: Secret scanning ────────────────────────────────────────────
    results: list[dict] = live_hosts  # default if --no-secrets
    if not args.no_secrets:
        print()
        results = scan_all_hosts(live_hosts, threads=args.threads, timeout=args.timeout)

    # ── Step 4: Summary & output ───────────────────────────────────────────
    print_summary(results)

    elapsed = time.time() - start_time
    log_info(f"Scan completed in {elapsed:.1f}s")

    if args.output:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
