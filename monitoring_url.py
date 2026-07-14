#!/usr/bin/python
import argparse
import csv
import socket
import sys
import time
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import whois as pywhois
except ImportError:
    pywhois = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None


REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (compatible; TakedownMonitorBot/1.0; +https://example.org/bot-info)"

# Simple heuristic for detecting CDN from HTTP headers
CDN_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare"],
    "akamai": ["akamai", "x-akamai"],
    "fastly": ["fastly", "x-served-by"],
    "amazon_cloudfront": ["cloudfront", "x-amz-cf-id"],
    "sucuri": ["x-sucuri-id"],
    "stackpath": ["stackpath"],
}


def normalize_target(raw: str):
    """Convert input into (hostname, url_to_check)."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None, None

    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        hostname = parsed.hostname
        url = raw
    else:
        hostname = raw
        url = f"http://{raw}"

    return hostname, url


def resolve_ip(hostname: str):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def check_http_status(url: str):
    """Check HTTP status + fetch headers for CDN detection. Try https then http."""
    headers = {"User-Agent": USER_AGENT}
    candidates = []
    if url.startswith("http://"):
        candidates = [url.replace("http://", "https://", 1), url]
    elif url.startswith("https://"):
        candidates = [url, url.replace("https://", "http://", 1)]
    else:
        candidates = [url]

    for candidate in candidates:
        try:
            resp = requests.get(
                candidate,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
            return resp.status_code, dict(resp.headers), candidate
        except requests.RequestException:
            continue
    return None, {}, None


def detect_cdn(response_headers: dict):
    if not response_headers:
        return ""
    header_blob = " ".join(f"{k}:{v}" for k, v in response_headers.items()).lower()
    detected = []
    for cdn_name, signatures in CDN_SIGNATURES.items():
        if any(sig in header_blob for sig in signatures):
            detected.append(cdn_name)
    return ", ".join(detected)


def whois_domain_lookup(hostname: str):
    """WHOIS lookup for a domain (not an IP). Returns (registrar, abuse_email_domain)."""
    if pywhois is None or not hostname or hostname.replace(".", "").isdigit():
        return "", ""
    try:
        w = pywhois.whois(hostname)
        registrar = w.registrar or ""
        abuse = w.get("emails")
        if isinstance(abuse, list):
            abuse = ", ".join(abuse)
        elif abuse is None:
            abuse = ""
        return registrar, abuse
    except Exception:
        return "", ""


def whois_ip_lookup(ip: str):
    """WHOIS/RDAP lookup for an IP -> hosting provider (ASN org) & abuse contact."""
    if IPWhois is None or not ip:
        return "", ""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        hosting_org = result.get("network", {}).get("name") or result.get("asn_description") or ""
        abuse_email = ""
        objects = result.get("objects", {})
        for _, obj_data in objects.items():
            roles = obj_data.get("roles") or []
            if "abuse" in [r.lower() for r in roles]:
                contact = obj_data.get("contact") or {}
                emails = contact.get("email") or []
                if isinstance(emails, list) and emails:
                    abuse_email = emails[0].get("value", "")
                break
        return hosting_org, abuse_email
    except Exception:
        return "", ""


def process_target(raw_line: str):
    hostname, url = normalize_target(raw_line)
    if not hostname:
        return None

    row = {
        "input": raw_line.strip(),
        "hostname": hostname,
        "status": "DOWN / UNREACHABLE",
        "http_code": "",
        "final_url": "",
        "ip_address": "",
        "cdn_detected": "",
        "domain_registrar": "",
        "domain_abuse_email": "",
        "hosting_org": "",
        "hosting_abuse_email": "",
    }

    ip = resolve_ip(hostname)
    row["ip_address"] = ip or "N/A"

    code, headers, final_url = check_http_status(url)
    if code is not None:
        row["status"] = "UP"
        row["http_code"] = str(code)
        row["final_url"] = final_url
        row["cdn_detected"] = detect_cdn(headers)

    registrar, domain_abuse = whois_domain_lookup(hostname)
    row["domain_registrar"] = registrar
    row["domain_abuse_email"] = domain_abuse

    if ip:
        hosting_org, hosting_abuse = whois_ip_lookup(ip)
        row["hosting_org"] = hosting_org
        row["hosting_abuse_email"] = hosting_abuse

    return row


def main():
    parser = argparse.ArgumentParser(
        description="Monitor a list of pirated domains/URLs & collect hosting info for takedown reports."
    )
    parser.add_argument("--input", "-i", required=True, help="File containing the list of domains/URLs (one per line)")
    parser.add_argument("--output", "-o", default="takedown_report.csv", help="Output CSV file path")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests (seconds), default 1.0")
    args = parser.parse_args()

    try:
        with open(args.input, "r", encoding="utf-8") as f:
            lines = [l for l in f.readlines() if l.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    fieldnames = [
        "input", "hostname", "status", "http_code", "final_url",
        "ip_address", "cdn_detected",
        "domain_registrar", "domain_abuse_email",
        "hosting_org", "hosting_abuse_email",
    ]

    results = []
    total = len(lines)
    for idx, line in enumerate(lines, 1):
        print(f"[{idx}/{total}] Processing: {line.strip()}")
        row = process_target(line)
        if row:
            results.append(row)
        time.sleep(args.delay)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    up_count = sum(1 for r in results if r["status"] == "UP")
    print(f"\nDone. {up_count}/{len(results)} sites are still up.")
    print(f"Report saved to: {args.output}")
    print("\nNote: use the 'hosting_abuse_email' / 'domain_abuse_email' columns to")
    print("send takedown reports (DMCA/abuse report) to the relevant hosting provider.")


if __name__ == "__main__":
    main()
