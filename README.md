# Piracy Takedown Monitor

A simple tool for monitoring a list of known domains/URLs streaming pirated
content (e.g. illegal PPV re-streams), and collecting public technical
information about that site's infrastructure to support **takedown reports
to hosting providers / CDNs**.

**What it collects:** site status (up/down), IP address, CDN in use
(Cloudflare, Fastly, etc.), domain registrar, and abuse contact emails for
the hosting/domain.

**What it does NOT collect:** any personal data about site visitors/viewers
(visitor IPs, cookies, etc.). All data gathered is public information tied
to the site's own infrastructure, not its end users.

## Installation

```bash
pip install requests python-whois ipwhois dnspython
```

## Usage

1. Create a text file listing the domains/URLs to monitor, one per line:

```
illegalstream1.com
https://illegalstream2.net/live/ppv
```

2. Run:

```bash
python3 piracy_takedown_monitor.py --input domains.txt --output report.csv
```

3. Open `report.csv` — key columns:
   - `status` — UP / DOWN
   - `ip_address`, `cdn_detected`
   - `domain_registrar`, `domain_abuse_email` — contact for reporting to the domain registrar
   - `hosting_org`, `hosting_abuse_email` — contact for reporting to the hosting/CDN provider

## After you get the report

1. For rows where `cdn_detected` is filled in (e.g. "cloudflare") — report
   through that CDN's official abuse form (e.g. https://abuse.cloudflare.com/),
   since the CDN is usually the first layer that can forward/act on reports
   to the actual origin server.
2. For rows without a CDN — email `hosting_abuse_email` directly with:
   the infringing URL, proof of broadcast rights ownership (e.g. PPV
   license), and screenshots/access logs as evidence.
3. Keep a record of reports sent (date, response, takedown status) outside
   this tool — a separate spreadsheet works fine — so you can track which
   sites have already been reported but reappeared (whack-a-mole is common
   in piracy cases).

## Limitations & notes

- WHOIS/RDAP lookups require access to port 43 (WHOIS) and RDAP endpoints,
  which corporate firewalls sometimes block — run this from a network that
  doesn't restrict them.
- Some registrars hide WHOIS data due to GDPR/privacy proxies — in that
  case, use the registrar's official abuse-reporting channel (all
  registrars are required to have one even when WHOIS is private).
- Run with a reasonable delay (`--delay`) so requests aren't mistaken for
  aggressive scraping/an attack by the target site.
- This tool is for gathering evidence and reporting contacts — it is not a
  substitute for legal process. For large or recurring cases, consider
  involving legal counsel or a professional anti-piracy service (e.g. a
  law firm handling IP enforcement).
