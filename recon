#!/usr/bin/env python3
import subprocess
import os
import csv
import socket
import argparse
import requests
import re
import html as htmllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- safer warning suppression (works across requests/urllib3 layouts) ---
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)  # [2](https://sqlpey.com/python/suppress-insecure-request-warning/)[3](https://gist.github.com/jcaxmacher/515fc27ea3a191cfdd4aca0350efecc7)

# For retries
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

FAST_TOOLS = [
    ["subfinder", "-d"],
    ["assetfinder", "--subs-only"],
    ["findomain", "-t"]
]

DEEP_TOOLS = [
    ["amass", "enum", "-passive", "-norecursive", "-d"]
]

KNOWN_DOMAINS_FILE = "known_domains.csv"

DEFAULT_TIMEOUT = 10
DEFAULT_MAX_WORKERS = 40
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Recon; StatusTitleSplitter) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
)
MAX_TITLE_BYTES = 200_000


# ==============================
# HELPERS
# ==============================

def which(cmd):
    """Return path if cmd exists in PATH else ''."""
    from shutil import which as _which
    return _which(cmd) or ""


def run_tool(cmd, debug_log=None):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 and debug_log:
            debug_log.write(f"[TOOL-ERR] {' '.join(cmd)}\n{result.stderr}\n\n")
        return result.stdout.splitlines()
    except Exception as e:
        if debug_log:
            debug_log.write(f"[TOOL-EXC] {' '.join(cmd)}\n{repr(e)}\n\n")
        return []


def normalize_domain(s):
    s = (s or "").strip().lower()
    s = s.replace("https://", "").replace("http://", "")
    s = s.split("/")[0]
    return s


def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return ""


def resolve_reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def load_known_domains(path):
    known = set()
    if not os.path.exists(path):
        return known

    header_candidates = {"domains", "domain", "hostname", "host", "fqdn", "url"}

    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        try:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("No headers")

            fieldnames = [x.strip().lower() for x in reader.fieldnames]
            key = None
            for fn in fieldnames:
                if fn in header_candidates:
                    key = fn
                    break
            if key is None:
                key = reader.fieldnames[0]  # fallback first column

            for row in reader:
                val = row.get(key)
                if val:
                    known.add(normalize_domain(val))
        except Exception:
            # headerless fallback
            f.seek(0)
            r = csv.reader(f)
            for row in r:
                if not row:
                    continue
                first = (row[0] or "").strip().lower()
                if first in header_candidates:
                    continue
                known.add(normalize_domain(row[0]))

    return known


# ==============================
# CT EXPANSION
# ==============================

def ct_expand(brand, session, debug_log=None):
    print(f"[+] Running light CT expansion for brand: {brand}")
    expanded_domains = set()

    try:
        url = f"https://crt.sh/?q=%25{brand}%25&output=json"
        r = session.get(url, timeout=20)
        if r.status_code != 200:
            return expanded_domains

        data = r.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            for domain in name_value.split("\n"):
                domain = domain.lower().strip().lstrip("*.")
                if brand not in domain:
                    continue
                if len(domain) > len(brand) + 20:
                    continue
                if not re.match(r"^[a-z0-9.-]+$", domain):
                    continue
                expanded_domains.add(domain)

    except Exception as e:
        if debug_log:
            debug_log.write(f"[CT-EXC] {repr(e)}\n")
        print(f"[!] CT expansion error: {e}")

    print(f"[+] CT Expansion Found: {len(expanded_domains)} related domains")
    return expanded_domains


# ==============================
# HTTP PROBING (STATUS != TITLE)
# ==============================

def build_session(user_agent, retries=2, backoff=0.3):
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})

    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["HEAD", "GET"])
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=200, pool_maxsize=200)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def extract_title_from_html(html_text):
    if not html_text:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html_text, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    title = htmllib.unescape(m.group(1))
    title = re.sub(r"\s+", " ", title).strip()
    return title


def fetch_status(session, url, timeout, verify_tls):
    """
    Return: (status_code, reason, location)
    Uses HEAD first; if HEAD returns 405 (method not allowed), tries GET without redirects.
    HEAD returning 405 is common on endpoints that only support GET. [1](https://stackoverflow.com/questions/75711757/fastapi-get-endpoint-returns-405-method-not-allowed-response)
    """
    try:
        r = session.head(url, timeout=timeout, allow_redirects=False, verify=verify_tls)
        if r.status_code == 405:
            # HEAD blocked -> try GET without redirects
            r = session.get(url, timeout=timeout, allow_redirects=False, verify=verify_tls, stream=True)
            r.close()
        return r.status_code, r.reason, r.headers.get("Location", "")
    except Exception:
        return "", "", ""


def fetch_title(session, url, timeout, verify_tls):
    """
    Follow redirects and extract real HTML <title>.
    Return: (final_url, final_status, title)
    """
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True, verify=verify_tls, stream=True)
        final_url = str(r.url)
        final_status = r.status_code
        ctype = (r.headers.get("Content-Type") or "").lower()

        if "text/html" not in ctype:
            r.close()
            return final_url, final_status, ""

        raw = b""
        for chunk in r.iter_content(chunk_size=4096):
            if not chunk:
                continue
            raw += chunk
            if len(raw) >= MAX_TITLE_BYTES:
                break
        r.close()

        enc = r.encoding or "utf-8"
        try:
            text = raw.decode(enc, errors="ignore")
        except Exception:
            text = raw.decode("utf-8", errors="ignore")

        return final_url, final_status, extract_title_from_html(text)

    except Exception:
        return "", "", ""


def probe_domain(domain, session, timeout, verify_tls):
    """
    Separate:
      - HTTP_Status/Reason/Location from HEAD/GET (no redirects)
      - Title from GET (redirects allowed)
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        sc, reason, loc = fetch_status(session, url, timeout, verify_tls)
        if sc:
            final_url, final_status, title = fetch_title(session, url, timeout, verify_tls)
            return {
                "HTTP_URL": url,
                "HTTP_Status": sc,
                "HTTP_Reason": reason,
                "Redirect_Location": loc,
                "Final_URL": final_url,
                "Final_Status": final_status,
                "Title": title
            }
    return {
        "HTTP_URL": "",
        "HTTP_Status": "",
        "HTTP_Reason": "",
        "Redirect_Location": "",
        "Final_URL": "",
        "Final_Status": "",
        "Title": ""
    }


# ==============================
# MAIN
# ==============================

def main(target, mode, expand, timeout, workers, verify_tls, debug):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = f"recon_{target}_{timestamp}"
    os.makedirs(base_dir, exist_ok=True)

    debug_log = None
    if debug:
        debug_path = os.path.join(base_dir, "debug.log")
        debug_log = open(debug_path, "w", encoding="utf-8")

    print(f"[+] Starting Recon for {target}")
    print(f"[+] Mode: {mode}")
    print(f"[+] Output dir: {base_dir}")

    # Preflight: check tools exist
    tools = FAST_TOOLS.copy()
    if mode == "deep":
        tools += DEEP_TOOLS

    print("[+] Preflight tool check:")
    for t in tools:
        exe = t[0]
        p = which(exe)
        print(f"    - {exe}: {'OK ' + p if p else 'MISSING'}")
        if not p and debug_log:
            debug_log.write(f"[MISSING-TOOL] {exe}\n")

    # Session (proxy env vars honored automatically by requests)
    session = build_session(DEFAULT_USER_AGENT)

    all_domains = set()

    # 1) ENUMERATION
    for tool in tools:
        exe = tool[0]
        if not which(exe):
            print(f"[!] Skipping missing tool: {exe}")
            continue

        cmd = tool + [target]
        print(f"[+] Running: {' '.join(cmd)}")
        for line in run_tool(cmd, debug_log=debug_log):
            d = normalize_domain(line)
            if d and "." in d:
                all_domains.add(d)

    # 2) CT EXPANSION
    if expand:
        brand = target.split(".")[0]
        expanded = ct_expand(brand, session, debug_log=debug_log)
        all_domains.update(expanded)

    print(f"[+] Total Unique Domains After Expansion: {len(all_domains)}")
    if not all_domains:
        print("[!] No domains found. (Tools missing? No output? Check debug.log)")
        if debug_log:
            debug_log.close()
        return

    # Save domains list
    domains_file = os.path.join(base_dir, "all_domains.txt")
    with open(domains_file, "w", encoding="utf-8") as f:
        for d in sorted(all_domains):
            f.write(d + "\n")

    # 3) Load known domains
    known_domains = load_known_domains(KNOWN_DOMAINS_FILE)

    # 4) Final CSV
    final_csv = os.path.join(base_dir, "final_output.csv")
    print("[+] Probing HTTP + generating final CSV...")

    fieldnames = [
        "Domain", "IP", "Reverse_DNS",
        "HTTP_Status", "HTTP_Reason", "Redirect_Location",
        "Final_URL", "Final_Status", "Title",
        "Domain_Status"
    ]

    def process_domain(domain):
        domain = normalize_domain(domain)

        http_info = probe_domain(domain, session, timeout, verify_tls)

        ip = resolve_ip(domain)
        reverse_dns = resolve_reverse_dns(ip) if ip else "N/A"
        domain_status = "Known" if domain in known_domains else "New"

        # If debugging, log empty probes for visibility
        if debug_log and not http_info["HTTP_Status"] and not http_info["Title"]:
            debug_log.write(f"[EMPTY-PROBE] {domain}\n")

        return {
            "Domain": domain,
            "IP": ip,
            "Reverse_DNS": reverse_dns,
            "HTTP_Status": http_info["HTTP_Status"],
            "HTTP_Reason": http_info["HTTP_Reason"],
            "Redirect_Location": http_info["Redirect_Location"],
            "Final_URL": http_info["Final_URL"],
            "Final_Status": http_info["Final_Status"],
            "Title": http_info["Title"],
            "Domain_Status": domain_status
        }

    with open(final_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(process_domain, d) for d in all_domains]
            for ftr in as_completed(futures):
                try:
                    writer.writerow(ftr.result())
                except Exception as e:
                    if debug_log:
                        debug_log.write(f"[WRITE-EXC] {repr(e)}\n")

    if debug_log:
        debug_log.close()

    print("[+] Recon Completed Successfully.")
    print(f"[+] Output CSV: {final_csv}")
    if debug:
        print(f"[+] Debug log: {os.path.join(base_dir, 'debug.log')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="External Recon Automation Tool (v3 - Status/Title separated; no httpx)"
    )
    parser.add_argument("target")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--expand", action="store_true")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS)
    parser.add_argument("--verify-tls", action="store_true", help="Verify TLS certs (default off)")
    parser.add_argument("--debug", action="store_true", help="Write debug.log in output folder")

    args = parser.parse_args()
    mode = "deep" if args.deep else "fast"

    main(
        target=args.target,
        mode=mode,
        expand=args.expand,
        timeout=args.timeout,
        workers=args.workers,
        verify_tls=args.verify_tls,
        debug=args.debug
    )
