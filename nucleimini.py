#!/usr/bin/env python3
import requests
import sys
import os
import argparse
import hashlib
import re
from datetime import datetime
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

headers = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Termux) MiniNuclei/1.5"
}

severity_color = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE
}

# === Deteksi Challenge / UAM ===
CHALLENGE_INDICATORS = [
    "just a moment",
    "checking your browser",
    "attention required",
    "cf-browser-verification",
    "challenge-platform",
    "cf-challenge",
    "ddos protection by cloudflare",
    "please wait while we check your browser",
    "ray id:",
    "cloudflare",
    "sucuri website firewall",
    "access denied",
    "imperva",
    "incapsula",
    "bot detection",
    "security check",
]

def is_challenge_page(response):
    """Deteksi apakah response adalah halaman challenge / UAM"""
    if response is None:
        return False

    text = (response.text or "").lower()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).lower() if title_match else ""

    # Status umum challenge
    if response.status_code in (403, 503, 429):
        for ind in CHALLENGE_INDICATORS:
            if ind in text or ind in title:
                return True

    # Cek string khas meskipun status 200
    for ind in CHALLENGE_INDICATORS:
        if ind in text or ind in title:
            return True

    return False

def banner():
    print(f"""{Fore.CYAN}
    __  ____       _   _            _      _ 
   |  \\/  (_)     | \\ | |          | |    (_)
   | \\  / |_ _ __ |  \\| |_   _  ___| | ___ _ 
   | |\\/| | | '_ \\| . ` | | | |/ __| |/ _ \\ |
   | |  | | | | | | |\\  | |_| | (__| |  __/ |
   |_|  |_|_|_| |_|_| \\_|\\__,_|\\___|_|\\___|_|
        Mini Nuclei - FarizalXploit (v1.5 - UAM Fix)
        Instagram: farizal_dzaky_anazili
    {Style.RESET_ALL}""")
    print(f"{Fore.YELLOW}[!] Hanya gunakan pada target yang kamu punya izin!{Style.RESET_ALL}\n")

def load_templates(file_path="templates.txt"):
    templates = []
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[!] File template '{file_path}' tidak ditemukan!{Style.RESET_ALL}")
        return templates

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 6:
                    templates.append({
                        "id": parts[0],
                        "path": parts[1],
                        "type": parts[2].lower(),
                        "value": parts[3],
                        "severity": parts[4].lower(),
                        "info": parts[5]
                    })
            except:
                continue
    return templates

def cek_target(base_url):
    base_url = base_url.strip()
    if not base_url:
        return None
    if not base_url.startswith(("http://", "https://")):
        base_url = "https://" + base_url
    if not base_url.endswith("/"):
        base_url += "/"
    return base_url

def normalize_text(text):
    """Buang bagian dinamis (token, angka panjang, ray-id, dll) supaya hash lebih stabil"""
    if not text:
        return ""
    # Buang angka panjang (token, timestamp, dll)
    text = re.sub(r'\b\d{6,}\b', '', text)
    # Buang ray-id / cf-ray style
    text = re.sub(r'[a-f0-9]{16,}', '', text, flags=re.IGNORECASE)
    # Buang whitespace berlebih
    text = re.sub(r'\s+', ' ', text)
    return text[:6000]

def get_signature(response):
    """Signature yang lebih stabil terhadap halaman challenge"""
    if response is None:
        return None
    text = response.text or ""
    normalized = normalize_text(text)
    return {
        "status": response.status_code,
        "length": len(response.content),
        "hash": hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()[:12],
        "is_challenge": is_challenge_page(response)
    }

def is_same_as_baseline(sig, baselines):
    """Cek apakah response mirip baseline (termasuk challenge)"""
    if not sig:
        return True

    # Kalau response-nya challenge, anggap sama dengan baseline challenge
    if sig.get("is_challenge"):
        for b in baselines:
            if b and b.get("is_challenge"):
                return True

    for b in baselines:
        if not b:
            continue
        if sig["status"] == b["status"]:
            # Toleransi length lebih longgar
            if abs(sig["length"] - b["length"]) < max(300, b["length"] * 0.25):
                if sig["hash"] == b["hash"]:
                    return True
    return False

def is_reachable(url, timeout=5):
    try:
        r = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        return True
    except Exception:
        return False

def save_findings(findings, output_file, target_url=None, mode="single"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, "a", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"Scan Time   : {timestamp}\n")
        if target_url:
            f.write(f"Target      : {target_url}\n")
        f.write(f"Mode        : {mode}\n")
        f.write("-" * 70 + "\n")
        
        if not findings:
            f.write("[!] Tidak ada temuan.\n\n")
            return
        
        for item in findings:
            f.write(f"[{item['severity'].upper()}] {item['id']} - {item['info']}\n")
            f.write(f"         └─ {item['url']}  (Status: {item['status']})\n\n")
        
        count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in findings:
            sev = item["severity"]
            if sev in count:
                count[sev] += 1
        
        f.write("-" * 70 + "\n")
        f.write(f"Total Temuan : {len(findings)}\n")
        f.write(f"Critical     : {count['critical']}\n")
        f.write(f"High         : {count['high']}\n")
        f.write(f"Medium       : {count['medium']}\n")
        f.write(f"Low          : {count['low']}\n")
        f.write(f"Info         : {count['info']}\n")
        f.write("=" * 70 + "\n\n")

def scan(url, templates, silent=False, output_file=None, strict=True, force=False):
    # === Cek apakah website bisa diakses dulu ===
    if not is_reachable(url, timeout=5):
        if not silent:
            print(f"{Fore.RED}[!] Website tidak bisa diakses → SKIP{Style.RESET_ALL}")
            print(f"    └─ {url}\n")
        else:
            print(f"{Fore.RED}    └─ Tidak bisa diakses → SKIP{Style.RESET_ALL}")
        return []

    if not silent:
        print(f"{Fore.BLUE}[*] Target         : {url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Total Template  : {len(templates)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Mode            : Strict (anti false-positive) = {strict}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Force           : {force}{Style.RESET_ALL}\n")

    findings = []
    baselines = []
    homepage_is_challenge = False

    # Ambil baseline (homepage + 404 palsu)
    if strict:
        try:
            r_home = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=False)
            sig_home = get_signature(r_home)
            baselines.append(sig_home)

            if sig_home and sig_home.get("is_challenge"):
                homepage_is_challenge = True
                if not force:
                    if not silent:
                        print(f"{Fore.RED}[!] Target terdeteksi Under Attack Mode / Challenge Page{Style.RESET_ALL}")
                        print(f"    └─ Semua path akan mengembalikan halaman yang sama → SKIP (pakai --force kalau mau paksa){Style.RESET_ALL}\n")
                    else:
                        print(f"{Fore.RED}    └─ UAM / Challenge terdeteksi → SKIP{Style.RESET_ALL}")
                    return []
                else:
                    if not silent:
                        print(f"{Fore.YELLOW}[!] Target UAM terdeteksi, tapi --force aktif → lanjut scan{Style.RESET_ALL}\n")
        except:
            pass

        try:
            fake_404 = urljoin(url, "this-path-does-not-exist-xyz-12345/")
            r_404 = requests.get(fake_404, headers=headers, timeout=8, verify=False, allow_redirects=False)
            baselines.append(get_signature(r_404))
        except:
            pass

    for template in templates:
        target_url = urljoin(url, template["path"].lstrip("/"))
        try:
            r = requests.get(
                target_url,
                headers=headers,
                timeout=10,
                verify=False,
                allow_redirects=False
            )

            sig = get_signature(r)
            found = False

            # Kalau response-nya challenge dan kita tidak force, skip
            if strict and not force and sig and sig.get("is_challenge"):
                continue

            # --- Matching Logic ---
            if template["type"] == "status":
                if str(r.status_code) == template["value"]:
                    if not strict or not is_same_as_baseline(sig, baselines):
                        found = True

            elif template["type"] == "keyword":
                keyword = template["value"].lower().strip()
                body = r.text.lower() if r.text else ""
                if keyword and keyword in body and len(keyword) >= 4:
                    # Keyword match hanya dianggap valid kalau bukan challenge page
                    if not (sig and sig.get("is_challenge")):
                        if not strict or not is_same_as_baseline(sig, baselines):
                            found = True

            if found:
                severity = template["severity"]
                color = severity_color.get(severity, Fore.WHITE)

                if not silent:
                    print(f"{color}[{severity.upper()}] {template['id']} - {template['info']}{Style.RESET_ALL}")
                    print(f"         └─ {target_url}  (Status: {r.status_code})\n")
                
                findings.append({
                    "id": template["id"],
                    "info": template["info"],
                    "severity": severity,
                    "url": target_url,
                    "status": r.status_code
                })

        except Exception:
            pass

    if not silent:
        print("-" * 60)
        if findings:
            count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev = f["severity"]
                if sev in count:
                    count[sev] += 1

            print(f"{Fore.GREEN}[✓] Selesai! Ditemukan {len(findings)} temuan (setelah filter FP):{Style.RESET_ALL}")
            print(f"    Critical : {count['critical']}")
            print(f"    High     : {count['high']}")
            print(f"    Medium   : {count['medium']}")
            print(f"    Low      : {count['low']}")
            print(f"    Info     : {count['info']}")
        else:
            print(f"{Fore.YELLOW}[!] Tidak ditemukan kerentanan dari template yang ada.{Style.RESET_ALL}")

    if output_file:
        save_findings(findings, output_file, target_url=url, mode="single")
        if not silent:
            print(f"{Fore.GREEN}[+] Hasil disimpan ke → {output_file}{Style.RESET_ALL}")

    return findings

def load_targets_from_file(file_path):
    targets = []
    if not os.path.exists(file_path):
        print(f"{Fore.RED}[!] File list '{file_path}' tidak ditemukan!{Style.RESET_ALL}")
        return targets

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets

def main():
    banner()

    parser = argparse.ArgumentParser(description="Mini Nuclei Scanner (v1.5 - UAM / Challenge Fix)")
    parser.add_argument("target", nargs="?", help="Single target URL")
    parser.add_argument("-l", "--list", dest="list_file", help="File list target")
    parser.add_argument("-t", "--templates", default="templates.txt", help="File template")
    parser.add_argument("-o", "--output", default="hasil.txt", help="File hasil")
    parser.add_argument("--no-strict", action="store_true", help="Matikan filter anti false-positive")
    parser.add_argument("--force", action="store_true", help="Paksa scan meskipun terdeteksi UAM / Challenge")
    args = parser.parse_args()

    templates = load_templates(args.templates)
    if not templates:
        print(f"{Fore.RED}[!] Tidak ada template yang berhasil dimuat.{Style.RESET_ALL}")
        return

    output_file = args.output
    strict = not args.no_strict
    force = args.force

    if os.path.exists(output_file):
        os.remove(output_file)

    if args.list_file:
        targets = load_targets_from_file(args.list_file)
        if not targets:
            print(f"{Fore.RED}[!] Tidak ada target di file list.{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Mode           : Mass Scan{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total Target   : {len(targets)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total Template : {len(templates)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Strict Mode    : {strict}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Force Mode     : {force}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Output File    : {output_file}{Style.RESET_ALL}\n")

        total_findings = 0
        targets_with_findings = 0
        skipped = 0

        for i, raw_target in enumerate(targets, 1):
            url = cek_target(raw_target)
            if not url:
                continue

            print(f"{Fore.MAGENTA}[{i}/{len(targets)}] Scanning → {url}{Style.RESET_ALL}")
            findings = scan(url, templates, silent=True, output_file=None, strict=strict, force=force)

            if findings is None:
                findings = []

            # Deteksi skip karena UAM
            if not findings:
                # Cek lagi apakah karena UAM
                try:
                    r = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
                    if is_challenge_page(r) and not force:
                        skipped += 1
                        print(f"{Fore.RED}    └─ UAM / Challenge → SKIP{Style.RESET_ALL}")
                    elif not is_reachable(url, timeout=3):
                        skipped += 1
                        print(f"{Fore.RED}    └─ Tidak bisa diakses → SKIP{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}    └─ Tidak ada temuan{Style.RESET_ALL}")
                except:
                    skipped += 1
                    print(f"{Fore.RED}    └─ Tidak bisa diakses → SKIP{Style.RESET_ALL}")
            else:
                total_findings += len(findings)
                targets_with_findings += 1
                save_findings(findings, output_file, target_url=url, mode="mass")
                print(f"{Fore.GREEN}    └─ {len(findings)} temuan{Style.RESET_ALL}")
            print()

        print("=" * 60)
        print(f"{Fore.GREEN}[✓] Mass Scan Selesai!{Style.RESET_ALL}")
        print(f"    Total Target dipindai : {len(targets)}")
        print(f"    Target yang vulnerabel: {targets_with_findings}")
        print(f"    Target di-skip        : {skipped}")
        print(f"    Total temuan          : {total_findings}")
        print(f"    Hasil disimpan di     : {output_file}")
        print("=" * 60)

    else:
        if args.target:
            target = args.target
        else:
            target = input("Masukkan URL target: ").strip()

        if not target:
            print(f"{Fore.RED}[!] Target tidak boleh kosong{Style.RESET_ALL}")
            return

        url = cek_target(target)
        if not url:
            print(f"{Fore.RED}[!] URL tidak valid{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Output File    : {output_file}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Strict Mode    : {strict}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Force Mode     : {force}{Style.RESET_ALL}\n")
        scan(url, templates, output_file=output_file, strict=strict, force=force)

if __name__ == "__main__":
    main()