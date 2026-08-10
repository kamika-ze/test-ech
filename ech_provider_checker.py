#!/usr/bin/env python3
"""
Two-stage domain classifier: Provider lookup + ECH support check (dig @1.1.1.1)
----------------------------------------------
This script runs in one of two modes, selected by a flag:

  --provider   Read a plain list of domains (--input) and, for each one,
               identify the hosting/CDN provider (Cloudflare, Google,
               Fastly, Akamai, Vercel, Fly.io, Bunny.net, Gcore, or
               Other). Writes ONE output file with columns:
                   Domain | Provider | ASN | Organization | IP

  --ech        Read the output of the --provider stage (--input) and,
               for each domain in it, check whether it publishes an ECH
               config. Writes ONE output file with the same columns as
               the input PLUS an ECH column (Yes/No) appended:
                   Domain | Provider | ASN | Organization | IP | ECH

Typical pipeline:
    python3 ech_provider_checker.py --provider -i domains.txt -o with_provider.csv -f csv
    python3 ech_provider_checker.py --ech      -i with_provider.csv -o with_ech.csv -f csv

Provider identification (used in --provider mode) works in this order:
  1. A local, zero-query check against Cloudflare's official IPv4 ranges.
  2. Team Cymru's DNS-based IP-to-ASN service (dig ...asn.cymru.com TXT),
     with results cached per IP (many domains behind the same CDN share
     a small pool of anycast IPs).
  3. NS records, CNAME records, and HTTP response headers, as a
     last-resort fallback.

Input formats:
  .txt  - one value per line. In --provider mode: one domain per line
          (optionally "domain<TAB>extra..." — only the first field is
          used). In --ech mode: a header line followed by tab-separated
          columns (as written by --provider mode with -f txt).
  .csv  - one row per line, comma-separated, with a header row.

Requirements:
    - `dig` must be installed and available in PATH
      (Debian/Ubuntu: sudo apt install dnsutils)
    - No external Python packages needed (uses subprocess + urllib only)
"""

import argparse
import csv
import ipaddress
import os
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

DNS_SERVER = "1.1.1.1"
DIG_TIMEOUT = 3
HTTP_TIMEOUT = 3
MAX_WORKERS = 120
DEBUG = False  # set True to print the raw dig command/output for every query

print_lock = threading.Lock()
asn_cache_lock = threading.Lock()
asn_cache = {}  # ip -> (asn_str, org_display), shared across threads to cut duplicate ASN lookups

# Official Cloudflare IPv4 ranges (source: https://www.cloudflare.com/ips-v4).
# Checked locally first (no extra DNS query) since Cloudflare accounts for
# the vast majority of domains observed in practice.
CLOUDFLARE_V4_NETS = [
    ipaddress.ip_network(cidr)
    for cidr in [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ]
]


def is_cloudflare_ip(ip: str) -> bool:
    if ip == "N/A":
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CLOUDFLARE_V4_NETS)


# Known Iranian filtering/DPI redirect ranges. When DNS queries are
# intercepted by ISP-level censorship infrastructure (which can happen
# even for queries aimed at 1.1.1.1, since interception often happens
# on the wire rather than at the resolver), the "answer" returned for a
# blocked domain is often a private/internal IP belonging to the
# filtering system itself rather than the domain's real IP.
IRAN_BLOCK_NETS = [
    ipaddress.ip_network("10.10.34.0/24"),  # observed redirect subnet
]


def is_blocked_or_private_ip(ip: str) -> bool:
    """
    True if `ip` looks like a censorship-infrastructure redirect or any
    other non-routable/private address rather than a real public IP —
    i.e. the DNS answer was almost certainly intercepted/rewritten, not
    a genuine response from the domain's actual provider.
    """
    if ip == "N/A":
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr in net for net in IRAN_BLOCK_NETS):
        return True
    # Any other private/reserved/loopback address is also never a
    # legitimate public answer for a real domain.
    return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local


# Provider display order / priority. Keyword lists are matched against
# the lowercased ASN organization name returned by Team Cymru.
PROVIDER_ASN_KEYWORDS = [
    ("Cloudflare", ["cloudflare"]),
    ("Google", ["google"]),
    ("Fastly", ["fastly"]),
    ("Akamai", ["akamai"]),
    ("Vercel", ["vercel"]),
    ("Fly.io", ["fly-io", "flyio", "fly.io"]),
    ("Bunny.net", ["bunny"]),
    ("Gcore", ["gcore", "g-core"]),
]

# Fallback signatures (only used if IP-range/ASN lookup is inconclusive)
PROVIDER_FALLBACK_SIGNATURES = [
    ("Cloudflare", {
        "ns": ["ns.cloudflare.com"],
        "cname": [],
        "header_any": ["cloudflare", "cf-ray"],
    }),
    ("Google", {
        "ns": ["googledomains.com", "ns-cloud"],
        "cname": ["googlehosted.com", "ghs.google.com", "googleusercontent.com"],
        "header_any": ["gws", "google frontend", "esf"],
    }),
    ("Fastly", {
        "ns": [],
        "cname": ["fastly.net", "fastlylb.net"],
        "header_any": ["fastly", "x-served-by", "x-fastly-request-id"],
    }),
    ("Akamai", {
        "ns": ["akam.net"],
        "cname": ["akamai.net", "akamaiedge.net", "edgekey.net", "edgesuite.net"],
        "header_any": ["akamaighost"],
    }),
    ("Vercel", {
        "ns": ["vercel-dns.com"],
        "cname": ["vercel-dns.com", "vercel.app"],
        "header_any": ["vercel", "x-vercel-id"],
    }),
    ("Fly.io", {
        "ns": [],
        "cname": ["fly.dev"],
        "header_any": ["fly.io", "fly-request-id"],
    }),
    ("Bunny.net", {
        "ns": [],
        "cname": ["b-cdn.net"],
        "header_any": ["bunnycdn"],
    }),
    ("Gcore", {
        "ns": [],
        "cname": ["gcdn.co", "gcorelabs.com"],
        "header_any": ["gcore"],
    }),
]


# --------------------------------------------------------------------------
# dig helpers
# --------------------------------------------------------------------------

def run_dig(query_name: str, record_type: str, server: str = DNS_SERVER) -> str:
    """Run `dig query_name record_type @server +options` and return raw stdout."""
    try:
        cmd = ["dig", query_name, record_type]
        if server:
            cmd.append(f"@{server}")
        cmd += ["+time=3", "+tries=1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=DIG_TIMEOUT)
        if DEBUG:
            with print_lock:
                print(f"    [debug] {' '.join(cmd)}\n    [debug] stdout: {result.stdout.strip()[:200]}")
        return result.stdout
    except Exception:
        return ""


def run_dig_short(query_name: str, record_type: str, server: str = DNS_SERVER) -> str:
    """Run `dig +short query_name record_type @server +options` and return raw stdout."""
    try:
        cmd = ["dig", "+short", query_name, record_type]
        if server:
            cmd.append(f"@{server}")
        cmd += ["+time=3", "+tries=1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=DIG_TIMEOUT)
        return result.stdout
    except Exception:
        return ""


def check_ech(domain: str) -> bool:
    """Check the HTTPS record for an ech= parameter."""
    output = run_dig(domain, "HTTPS")
    return "ech=" in output.lower()


def resolve_ip(domain: str, retries: int = 1) -> str:
    """Resolve the domain's A record IP using dig +short, with retries."""
    for attempt in range(retries + 1):
        output = run_dig_short(domain, "A")
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        for line in lines:
            parts = line.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return line
    return "N/A"


def lookup_asn_info(ip: str, retries: int = 1):
    """
    Look up the ASN number and organization name for an IP using Team
    Cymru's DNS-based IP-to-ASN service. Returns (asn_str, org_display).
    Cached per IP to avoid duplicate lookups at scale.
    """
    if ip == "N/A":
        return "N/A", "N/A"

    with asn_cache_lock:
        cached = asn_cache.get(ip)
    if cached is not None:
        return cached

    result = ("N/A", "N/A")
    for attempt in range(retries + 1):
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            origin_output = run_dig_short(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
            first_line = origin_output.strip().splitlines()[0] if origin_output.strip() else ""
            if not first_line:
                continue
            asn = first_line.strip('"').split("|")[0].strip()
            asn = asn.split(" ")[0]
            if not asn.isdigit():
                continue

            asname_output = run_dig_short(f"AS{asn}.asn.cymru.com", "TXT")
            asname_line = asname_output.strip().splitlines()[0] if asname_output.strip() else ""
            if not asname_line:
                continue
            fields = asname_line.strip('"').split("|")
            org_display = fields[-1].strip() if fields else ""
            if org_display:
                result = (f"AS{asn}", org_display)
                break
        except Exception:
            continue

    with asn_cache_lock:
        asn_cache[ip] = result
    return result


def get_ns_records(domain: str) -> str:
    return run_dig(domain, "NS").lower()


def get_cname_records(domain: str) -> str:
    return run_dig(domain, "CNAME").lower()


def get_http_headers_blob(domain: str, skip: bool = False) -> str:
    """
    Lightweight HEAD request to collect header text for fallback matching.
    Skipped entirely (returns "") if `skip` is True — used when the A
    record couldn't even be resolved, since an HTTP request would almost
    certainly fail too and only costs time.
    """
    if skip:
        return ""
    blob_parts = []
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{domain}", method="HEAD")
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                for k, v in resp.getheaders():
                    blob_parts.append(f"{k}: {v}".lower())
            if blob_parts:
                break
        except Exception:
            continue
    return " | ".join(blob_parts)


def identify_provider_by_asn(org_name: str) -> str:
    if not org_name:
        return ""
    for name, keywords in PROVIDER_ASN_KEYWORDS:
        for kw in keywords:
            if kw in org_name:
                return name
    return ""


def identify_provider_fallback(ns_blob: str, cname_blob: str, header_blob: str) -> str:
    for name, sig in PROVIDER_FALLBACK_SIGNATURES:
        for suffix in sig["ns"]:
            if suffix in ns_blob:
                return name
        for suffix in sig["cname"]:
            if suffix in cname_blob:
                return name
        for token in sig["header_any"]:
            if token in header_blob:
                return name
    return "Other"


# --------------------------------------------------------------------------
# I/O helpers
# --------------------------------------------------------------------------

def looks_like_domain(value: str) -> bool:
    """Very light sanity check used to skip an obvious CSV/TXT header row."""
    value = value.strip().lower()
    if not value:
        return False
    if value in ("domain", "domain_name", "hostname", "url", "site"):
        return False
    return True


def read_domains(input_path: str) -> list:
    """
    Read a plain domain list (used by --provider mode).
      - .txt: one domain per line; tolerant of "domain", "domain<TAB>ip",
        or "domain ip" lines (only the first field is used).
      - .csv: domain taken from the first column of each row; a header
        row is detected and skipped automatically.
    """
    ext = os.path.splitext(input_path)[1].lower()
    domains = []

    if ext == ".csv":
        with open(input_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if not row:
                    continue
                first_field = row[0].strip()
                if i == 0 and not looks_like_domain(first_field):
                    continue  # header row
                if first_field and not first_field.startswith("#"):
                    domains.append(first_field)
    else:
        with open(input_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                domain_only = line.split()[0]
                domains.append(domain_only)

    return domains


def read_table(input_path: str):
    """
    Read a header + rows table (used by --ech mode, i.e. the output of
    --provider mode). Returns (header: list[str], rows: list[list[str]]).
    Supports .csv (comma-separated) and .txt (tab-separated) files, both
    with a header line as the first row.
    """
    ext = os.path.splitext(input_path)[1].lower()

    if ext == ".csv":
        with open(input_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            rows = [row for row in reader if row]
    else:
        with open(input_path, "r", encoding="utf-8") as f:
            rows = [line.rstrip("\n").split("\t") for line in f if line.strip()]

    if not rows:
        return [], []

    header = rows[0]
    data_rows = rows[1:]
    return header, data_rows


def write_table(path: str, header: list, rows: list, output_format: str):
    """rows is a list of lists/tuples, same column count as header."""
    if output_format == "csv":
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\t".join(header) + "\n")
            for row in rows:
                f.write("\t".join(str(v) for v in row) + "\n")


# --------------------------------------------------------------------------
# Stage workers
# --------------------------------------------------------------------------

SKIP_HTTP_FALLBACK = False  # set via --no-http-fallback


def classify_provider(index: int, total: int, domain: str):
    """
    --provider mode worker. Returns (domain, provider, asn, org, ip).
    """
    ip = resolve_ip(domain)

    if is_blocked_or_private_ip(ip):
        with print_lock:
            print(f"[{index}/{total}] {domain}  BLOCKED/FILTERED (ip={ip})")
        return domain, "Blocked/Filtered (IR)", "N/A", "N/A", ip

    asn, org = lookup_asn_info(ip)

    provider = identify_provider_by_asn(org.lower()) if org != "N/A" else ""
    method = "asn"

    if not provider and is_cloudflare_ip(ip):
        provider = "Cloudflare"
        method = "ip-range"

    if not provider:
        # Skip the HTTP fallback (and its worst-case ~10s cost) when we
        # couldn't even resolve an A record, or when disabled globally —
        # an HTTP request would almost certainly fail too.
        skip_http = SKIP_HTTP_FALLBACK or ip == "N/A"
        ns_blob = get_ns_records(domain)
        cname_blob = get_cname_records(domain)
        header_blob = get_http_headers_blob(domain, skip=skip_http)
        provider = identify_provider_fallback(ns_blob, cname_blob, header_blob)
        method = "fallback"

    with print_lock:
        print(f"[{index}/{total}] {domain}  provider={provider} ({method})  asn={asn}  org={org}  ip={ip}")

    return domain, provider, asn, org, ip


def check_ech_worker(index: int, total: int, domain: str):
    """--ech mode worker. Returns (domain, ech_yes_no)."""
    has_ech = check_ech(domain)
    ech_display = "Yes" if has_ech else "No"
    with print_lock:
        print(f"[{index}/{total}] {domain}  ECH={ech_display}")
    return domain, ech_display


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------

def run_provider_mode(args):
    domains = read_domains(args.input)
    if not domains:
        print(f"[!] File {args.input} is empty or no domains could be read from it.")
        sys.exit(1)

    if args.top_n is not None:
        domains = domains[: args.top_n]

    total = len(domains)
    print(f"[*] Identifying provider for {total} domains against {DNS_SERVER} with {MAX_WORKERS} concurrent workers ...\n")

    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(classify_provider, i, total, domain): domain
            for i, domain in enumerate(domains, 1)
        }
        for future in as_completed(futures):
            domain, provider, asn, org, ip = future.result()
            results[domain] = (provider, asn, org, ip)

    header = ["Domain", "Provider", "ASN", "Organization", "IP"]
    rows = [[domain, *results[domain]] for domain in domains]

    write_table(args.output, header, rows, args.format)

    print(f"\n[+] Done. {total} domains classified -> {args.output}")
    counts = {}
    for row in rows:
        counts[row[1]] = counts.get(row[1], 0) + 1
    for provider, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {provider}: {count}")


def run_ech_mode(args):
    header, data_rows = read_table(args.input)
    if not header or not data_rows:
        print(f"[!] File {args.input} is empty or has no data rows.")
        sys.exit(1)

    if "Domain" not in header:
        print(f"[!] Input file {args.input} has no 'Domain' column (found: {header}).")
        sys.exit(1)
    domain_idx = header.index("Domain")

    if args.top_n is not None:
        data_rows = data_rows[: args.top_n]

    domains = [row[domain_idx] for row in data_rows]
    total = len(domains)
    print(f"[*] Checking ECH support for {total} domains against {DNS_SERVER} with {MAX_WORKERS} concurrent workers ...\n")

    ech_results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_ech_worker, i, total, domain): domain
            for i, domain in enumerate(domains, 1)
        }
        for future in as_completed(futures):
            domain, ech_display = future.result()
            ech_results[domain] = ech_display

    new_header = header + ["ECH"]
    new_rows = [row + [ech_results[row[domain_idx]]] for row in data_rows]

    write_table(args.output, new_header, new_rows, args.format)

    yes_count = sum(1 for v in ech_results.values() if v == "Yes")
    print(f"\n[+] Done. {yes_count} out of {total} domains support ECH -> {args.output}")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main():
    global MAX_WORKERS, SKIP_HTTP_FALLBACK

    parser = argparse.ArgumentParser(
        description="Two-stage domain classifier: provider lookup, then ECH support check."
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--provider", action="store_true",
        help="Mode 1: read a plain domain list and identify each domain's hosting/CDN provider.",
    )
    mode_group.add_argument(
        "--ech", action="store_true",
        help="Mode 2: read the output of --provider mode and check ECH support for each domain.",
    )
    parser.add_argument("-i", "--input", required=True, help="Path to the input file (.txt or .csv)")
    parser.add_argument("-o", "--output", required=True, help="Path to the single output file to write (.txt or .csv)")
    parser.add_argument(
        "-f", "--format", choices=["txt", "csv"], default="txt",
        help="Output file format (default: txt, tab-separated)",
    )
    parser.add_argument(
        "-n", "--top-n", type=int, default=None,
        help="Only process the first N domains/rows from the input file, in input order. Default: process all.",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=MAX_WORKERS,
        help=f"Number of concurrent worker threads (default: {MAX_WORKERS}). Higher = faster, but more "
             "load on the DNS resolver; lower it if you see a lot of timeouts.",
    )
    parser.add_argument(
        "--no-http-fallback", action="store_true",
        help="Disable the HTTP header fallback check in --provider mode (faster, but a bit less accurate "
             "for domains not identifiable via IP range or ASN).",
    )
    args = parser.parse_args()

    MAX_WORKERS = args.workers
    SKIP_HTTP_FALLBACK = args.no_http_fallback

    try:
        subprocess.run(["dig", "-v"], capture_output=True, timeout=5)
    except FileNotFoundError:
        print("[!] `dig` was not found. Install it first, e.g.: sudo apt install dnsutils")
        sys.exit(1)
    except Exception:
        pass

    if not os.path.isfile(args.input):
        print(f"[!] File {args.input} not found.")
        sys.exit(1)

    output_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(output_dir, exist_ok=True)

    if args.provider:
        run_provider_mode(args)
    else:
        run_ech_mode(args)


if __name__ == "__main__":
    main()
