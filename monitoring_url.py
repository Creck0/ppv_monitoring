#!/usr/bin/python
import argparse
import csv
import socket
import sys
import time
from datetime import datetime
from urllib.parse import urlparse
import requests
import urllib3
from pathlib import Path

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Optional dependencies
try:
    import whois as pywhois
except ImportError:
    pywhois = None
try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("[WARNING] reportlab tidak terinstal. PDF report tidak akan dibuat.")

REQUEST_TIMEOUT = 12
USER_AGENT = "Mozilla/5.0 (compatible; TakedownMonitorBot/1.1; +https://example.org/bot-info)"

CDN_SIGNATURES = {
    "cloudflare": ["cf-ray", "cloudflare"],
    "akamai": ["akamai", "x-akamai"],
    "fastly": ["fastly", "x-served-by"],
    "amazon_cloudfront": ["cloudfront", "x-amz-cf-id"],
    "sucuri": ["x-sucuri-id"],
    "stackpath": ["stackpath"],
    "google": ["google", "gws"],
}

def normalize_target(raw: str):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None, None
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        hostname = parsed.hostname or raw
        url = raw
    else:
        hostname = raw
        url = f"https://{raw}"
    return hostname, url

def resolve_ip(hostname: str):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def check_http_status(url: str):
    headers = {"User-Agent": USER_AGENT}
    candidates = [url]
    if url.startswith("http://"):
        candidates.append(url.replace("http://", "https://", 1))
    elif url.startswith("https://"):
        candidates.append(url.replace("https://", "http://", 1))
    
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
        return "Tidak terdeteksi"
    header_blob = " ".join(f"{k}:{v}" for k, v in response_headers.items()).lower()
    detected = []
    for cdn_name, signatures in CDN_SIGNATURES.items():
        if any(sig in header_blob for sig in signatures):
            detected.append(cdn_name.replace("_", " ").title())
    return ", ".join(detected) if detected else "Tidak terdeteksi"

def whois_domain_lookup(hostname: str):
    if pywhois is None or not hostname or hostname.replace(".", "").isdigit():
        return "", ""
    try:
        w = pywhois.whois(hostname)
        registrar = getattr(w, 'registrar', "") or ""
        emails = getattr(w, 'emails', None)
        abuse = ", ".join(emails) if isinstance(emails, list) else str(emails) if emails else ""
        return registrar, abuse
    except Exception:
        return "", ""

def whois_ip_lookup(ip: str):
    if IPWhois is None or not ip:
        return "", ""
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        hosting_org = result.get("network", {}).get("name") or result.get("asn_description", "")
        abuse_email = ""
        for _, obj_data in result.get("objects", {}).items():
            if "abuse" in [r.lower() for r in obj_data.get("roles", [])]:
                contact = obj_data.get("contact", {})
                emails = contact.get("email", [])
                if emails and isinstance(emails, list):
                    abuse_email = emails[0].get("value", "")
                break
        return hosting_org, abuse_email
    except Exception:
        return "", ""

def generate_pdf_report(results, output_path="takedown_report.pdf"):
    if not PDF_AVAILABLE:
        return False
    try:
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=30)
        story.append(Paragraph("Piracy Takedown Report", title_style))
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))

        # Summary
        up_count = sum(1 for r in results if r.get("status") == "UP")
        story.append(Paragraph(f"Total Target: {len(results)} | Active Sites: {up_count}", styles['Heading2']))
        story.append(Spacer(1, 12))

        # Table data
        table_data = [["No", "Input", "Hostname", "Status", "HTTP", "IP Address", "CDN", "Hosting Org", "Abuse Email"]]
        for i, row in enumerate(results, 1):
            table_data.append([
                str(i),
                row["input"][:35],
                row["hostname"],
                row["status"],
                row["http_code"] or "-",
                row["ip_address"] or "N/A",
                row["cdn_detected"],
                row["hosting_org"][:25] or "-",
                row["hosting_abuse_email"] or row["domain_abuse_email"] or "-"
            ])

        table = Table(table_data, colWidths=[30, 100, 90, 50, 40, 80, 70, 90, 110])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
        story.append(Spacer(1, 30))

        # Footer note
        note_style = ParagraphStyle('Note', parent=styles['Normal'], fontSize=9, textColor=colors.red)
        story.append(Paragraph("Catatan: Gunakan kolom Abuse Email untuk mengirim DMCA / Abuse Report ke provider terkait.", note_style))
        story.append(Paragraph("Hanya data publik infrastruktur yang dikumpulkan. Tidak ada data pribadi.", styles['Normal']))

        doc.build(story)
        return True
    except Exception as e:
        print(f"[ERROR] Gagal membuat PDF: {e}")
        return False

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
    parser = argparse.ArgumentParser(description="Piracy Takedown Monitor - Versi Legal")
    parser.add_argument("--input", "-i", required=True, help="File input daftar domain/URL")
    parser.add_argument("--output", "-o", default="takedown_report", help="Nama file output (tanpa ekstensi)")
    parser.add_argument("--delay", type=float, default=1.2, help="Delay antar request (detik)")
    parser.add_argument("--screenshot", action="store_true", help="Ambil screenshot (butuh selenium)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] File input tidak ditemukan: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        lines = [line for line in f if line.strip() and not line.strip().startswith("#")]

    fieldnames = ["input", "hostname", "status", "http_code", "final_url", "ip_address",
                  "cdn_detected", "domain_registrar", "domain_abuse_email",
                  "hosting_org", "hosting_abuse_email"]

    results = []
    total = len(lines)

    print(f"Memulai monitoring {total} target...\n")

    for idx, line in enumerate(lines, 1):
        print(f"[{idx:3d}/{total}] Memproses: {line.strip()}")
        row = process_target(line)
        if row:
            results.append(row)
        time.sleep(args.delay)

    # Save CSV
    csv_path = f"{args.output}.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # Generate PDF
    pdf_path = f"{args.output}.pdf"
    pdf_success = generate_pdf_report(results, pdf_path)

    up_count = sum(1 for r in results if r["status"] == "UP")
    print("\n" + "="*60)
    print("PROSES SELESAI")
    print("="*60)
    print(f"Total target     : {len(results)}")
    print(f"Situs aktif      : {up_count}")
    print(f"CSV Report       : {csv_path}")
    if pdf_success:
        print(f"PDF Report       : {pdf_path}")
    print("\nGunakan kolom 'hosting_abuse_email' atau 'domain_abuse_email' untuk laporan takedown.")
    print("Pastikan laporan Anda sesuai prosedur DMCA / abuse policy provider.")

if __name__ == "__main__":
    main()
