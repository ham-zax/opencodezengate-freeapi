#!/usr/bin/env python3
"""
Scrape all free proxy pages from proxyhub.me, filter protocols supported by
ZenGate (http/socks5), and push them to ZenGate via POST /api/proxies.
The upstream ZenGate runtime only supports socks5/http; SOCKS4 is skipped.
"""
import os, sys, time, json, urllib.request

BASE = "https://proxyhub.me/zh/all-free-proxy-list.html"
GATE = os.environ.get("GATE_URL", "http://127.0.0.1:13339/api/proxies")
TOTAL_PAGES = int(os.environ.get("TOTAL_PAGES", "100"))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "proxyhub_push.log")
log = open(LOG_FILE, "a", encoding="utf-8")

def out(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, file=sys.stderr)
    log.write(line + "\n")
    log.flush()

def fetch(url, retries=3):
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            if i == retries - 1:
                out(f"  Fetch failed {url}: {e}")
                return None
            time.sleep(2)

def parse_page(html):
    rows = []
    m = re.search(r"<tbody[^>]*>(.*?)</tbody>", html, re.S)
    if not m:
        return rows
    for tr in re.findall(r"<tr>.*?</tr>", m.group(1), re.S):
        ip_m = re.search(r'ip-text"[^>]*>([\d.]+)', tr)
        port_m = re.search(r'port-text">(\d+)', tr)
        if not ip_m or not port_m:
            continue
        # Match protocol title or chip text
        protos = re.findall(r'protocol-chip[^"]*"[^>]*title="([^"]+)"', tr)
        if not protos:
            protos = re.findall(r'protocol-chip[^"]*"[^>]*>\s*<span>([^<]+)</span>', tr)
        rows.append((ip_m.group(1), port_m.group(1), protos))
    return rows

def push(proxies):
    """proxies: list of 'ip:port' or 'socks5://ip:port'"""
    if not proxies:
        out("  No proxies to push")
        return 0
    body = json.dumps({"proxies": proxies}).encode()
    req = urllib.request.Request(GATE, data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read().decode())
            out(f"  Push successful: {resp}")
            return resp.get("count", 0)
    except Exception as e:
        out(f"  Push failed: {e}")
        return 0

def main():
    import re
    # Allow overriding pages from command-line argument (e.g. python3 push_proxyhub.py 5)
    pages = TOTAL_PAGES
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        pages = int(sys.argv[1])

    out(f"========== Starting crawl of proxyhub.me (pages: {pages}) ==========")
    out(f"Target Gateway: {GATE}")
    seen = set()
    http, socks5 = [], []
    for page in range(1, pages + 1):
        url = BASE if page == 1 else f"{BASE}?page={page}"
        html = fetch(url)
        if not html:
            out(f"  page {page}: Skipped")
            continue
        rows = parse_page(html)
        for ip, port, protos in rows:
            ep = f"{ip}:{port}"
            if ep in seen:
                continue
            seen.add(ep)
            up = [p.upper() for p in protos]
            if any("SOCKS5" in p for p in up):
                socks5.append(f"socks5://{ep}")
            elif any(p in ("HTTP", "HTTPS", "HTTP/HTTPS", "SSL") for p in up):
                http.append(ep)
            # Skip SOCKS4 etc.
        if page % 10 == 0 or page == pages:
            out(f"  Scraped {page}/{pages} pages, cumulative http+{len(http)} socks5+{len(socks5)}")
        time.sleep(0.8)

    out(f"Crawl complete: HTTP/HTTPS {len(http)} items, SOCKS5 {len(socks5)} items")
    # Push in batches (500 per batch)
    added = 0
    for batch in [http[i:i+500] for i in range(0, len(http), 500)]:
        added += push(batch)
    for batch in [socks5[i:i+500] for i in range(0, len(socks5), 500)]:
        added += push(batch)
    out(f"========== Added {added} proxies this run ==========\n")

if __name__ == "__main__":
    import re
    main()
