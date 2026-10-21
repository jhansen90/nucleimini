#!/usr/bin/env python3
"""
Filter Live Hosts
Membaca list domain/URL, cek mana yang masih hidup, simpan hanya yang live.

Usage:
    python3 filter_live.py -f subdo.txt -o live.txt
    python3 filter_live.py -f subdo.txt -o live.txt -w 20 --timeout 8
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

# ======================== CONFIG ========================
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Status code yang dianggap "hidup"
LIVE_CODES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}

DEFAULT_WORKERS = 15
DEFAULT_TIMEOUT = 8
# ========================================================


def normalize_url(line: str) -> str:
    """Pastikan URL punya scheme"""
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    if not line.startswith(("http://", "https://")):
        line = "https://" + line
    return line.rstrip("/")


def check_live(url: str, timeout: int) -> tuple:
    """
    Return (url, is_live, status_code_or_error)
    """
    try:
        # Coba HEAD dulu (lebih ringan)
        resp = requests.head(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )
        code = resp.status_code

        # Beberapa server tidak support HEAD → fallback GET
        if code == 405 or code == 501:
            resp = requests.get(
                url,
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=True,
                stream=True,  # jangan download full body
            )
            code = resp.status_code
            resp.close()

        is_live = code in LIVE_CODES
        return (url, is_live, code)

    except requests.exceptions.SSLError:
        # SSL error tapi host merespons → anggap hidup (masih bisa diakses)
        return (url, True, "SSL_ERROR")
    except requests.exceptions.ConnectTimeout:
        return (url, False, "TIMEOUT")
    except requests.exceptions.ReadTimeout:
        return (url, False, "READ_TIMEOUT")
    except requests.exceptions.ConnectionError as e:
        err = str(e)
        if "NameResolutionError" in err or "Failed to resolve" in err:
            return (url, False, "DNS_FAIL")
        if "Network is unreachable" in err:
            return (url, False, "UNREACHABLE")
        return (url, False, "CONN_ERROR")
    except Exception as e:
        return (url, False, f"ERROR:{type(e).__name__}")


def main():
    parser = argparse.ArgumentParser(description="Filter hanya host yang masih hidup")
    parser.add_argument("-f", "--file", required=True, help="Input file (subdo.txt)")
    parser.add_argument("-o", "--output", default="live.txt", help="Output file (default: live.txt)")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help=f"Threads (default: {DEFAULT_WORKERS})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout detik (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-q", "--quiet", action="store_true", help="Hanya tampilkan ringkasan")
    args = parser.parse_args()

    # Baca input
    try:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] File tidak ditemukan: {args.file}")
        sys.exit(1)

    urls = []
    for line in raw_lines:
        u = normalize_url(line)
        if u:
            urls.append(u)

    # Unique
    urls = sorted(set(urls))

    if not urls:
        print("[!] Tidak ada URL valid di file.")
        sys.exit(1)

    print("=" * 60)
    print("  Live Host Filter")
    print("=" * 60)
    print(f"[*] Total URL unik     : {len(urls)}")
    print(f"[*] Workers            : {args.workers}")
    print(f"[*] Timeout            : {args.timeout}s")
    print(f"[*] Output             : {args.output}")
    print()

    live = []
    dead = 0
    start = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(check_live, url, args.timeout): url
            for url in urls
        }

        done = 0
        for future in as_completed(futures):
            done += 1
            url, is_live, info = future.result()

            if is_live:
                live.append(url)
                if not args.quiet:
                    print(f"[LIVE]  {url}  ({info})")
            else:
                dead += 1
                if not args.quiet:
                    print(f"[DEAD]  {url}  ({info})")

            # progress tiap 50
            if done % 50 == 0:
                print(f"        ... progress {done}/{len(urls)}")

    elapsed = time.time() - start

    # Simpan hasil
    with open(args.output, "w", encoding="utf-8") as f:
        for u in sorted(live):
            f.write(u + "\n")

    print()
    print("=" * 60)
    print("  HASIL FILTER")
    print("=" * 60)
    print(f"Total dicek     : {len(urls)}")
    print(f"LIVE            : {len(live)}")
    print(f"DEAD / Error    : {dead}")
    print(f"Waktu           : {elapsed:.1f} detik")
    print(f"Disimpan ke     : {args.output}")
    print()


if __name__ == "__main__":
    main()
