#!/usr/bin/env python3
import requests
import sys
import os
import argparse
import hashlib
from datetime import datetime
from urllib.parse import urljoin
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

headers = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Termux) MiniNuclei/1.4"
}

severity_color = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE
}

def banner():
    print(f"""{Fore.CYAN}
    __  ____       _   _            _      _ 
   |  \\/  (_)     | \\ | |          | |    (_)
   | \\  / |_ _ __ |  \\| |_   _  ___| | ___ _ 
   | |\\/| | | '_ \\| . ` | | | |/ __| |/ _ \\ |
   | |  | | | | | | |\\  | |_| | (__| |  __/ |
   |_|  |_|_|_| |_|_| \\_|\\__,_|\\___|_|\\___|_|
        Mini Nuclei - FarizalXploit (Fixed FP)
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

def get_signature(response):
    """Buat signature sederhana dari response untuk deteksi soft-404"""
    if response is None:
        return None
    text = response.text[:8000] if response.text else ""
    return {
        "status": response.status_code,
        "length": len(response.content),
        "hash": hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()[:12]
    }

def is_same_as_baseline(sig, baselines):
    """Cek apakah response mirip homepage atau soft-404"""
    if not sig:
        return True
    for b in baselines:
        if not b:
            continue
        # Status sama + panjang mirip (±15%) + hash sama → dianggap sama
        if sig["status"] == b["status"]:
            if abs(sig["length"] - b["length"]) < max(150, b["length"] * 0.15):
                if sig["hash"] == b["hash"]:
                    return True
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

def scan(url, templates, silent=False, output_file=None, strict=True):
    if not silent:
        print(f"{Fore.BLUE}[*] Target         : {url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Total Template  : {len(templates)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[*] Mode            : Strict (anti false-positive) = {strict}{Style.RESET_ALL}\n")

    findings = []
    baselines = []

    # Ambil baseline (homepage + 404 palsu)
    if strict:
        try:
            r_home = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=False)
            baselines.append(get_signature(r_home))
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

            # --- Matching Logic yang lebih ketat ---
            if template["type"] == "status":
                if str(r.status_code) == template["value"]:
                    # Hanya terima jika BUKAN soft-404 / sama dengan baseline
                    if not strict or not is_same_as_baseline(sig, baselines):
                        found = True

            elif template["type"] == "keyword":
                keyword = template["value"].lower().strip()
                body = r.text.lower() if r.text else ""
                if keyword and keyword in body:
                    # Extra check: keyword tidak terlalu generik + response berbeda
                    if len(keyword) >= 4:          # hindari keyword terlalu pendek
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

    parser = argparse.ArgumentParser(description="Mini Nuclei Scanner (Fixed False Positive)")
    parser.add_argument("target", nargs="?", help="Single target URL")
    parser.add_argument("-l", "--list", dest="list_file", help="File list target")
    parser.add_argument("-t", "--templates", default="templates.txt", help="File template")
    parser.add_argument("-o", "--output", default="hasil.txt", help="File hasil")
    parser.add_argument("--no-strict", action="store_true", help="Matikan filter anti false-positive")
    args = parser.parse_args()

    templates = load_templates(args.templates)
    if not templates:
        print(f"{Fore.RED}[!] Tidak ada template yang berhasil dimuat.{Style.RESET_ALL}")
        return

    output_file = args.output
    strict = not args.no_strict

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
        print(f"{Fore.CYAN}[*] Output File    : {output_file}{Style.RESET_ALL}\n")

        total_findings = 0
        targets_with_findings = 0

        for i, raw_target in enumerate(targets, 1):
            url = cek_target(raw_target)
            if not url:
                continue

            print(f"{Fore.MAGENTA}[{i}/{len(targets)}] Scanning → {url}{Style.RESET_ALL}")
            findings = scan(url, templates, silent=True, output_file=None, strict=strict)

            if findings:
                total_findings += len(findings)
                targets_with_findings += 1
                save_findings(findings, output_file, target_url=url, mode="mass")
                print(f"{Fore.GREEN}    └─ {len(findings)} temuan{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}    └─ Tidak ada temuan{Style.RESET_ALL}")
            print()

        print("=" * 60)
        print(f"{Fore.GREEN}[✓] Mass Scan Selesai!{Style.RESET_ALL}")
        print(f"    Total Target dipindai : {len(targets)}")
        print(f"    Target yang vulnerabel: {targets_with_findings}")
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
        print(f"{Fore.CYAN}[*] Strict Mode    : {strict}{Style.RESET_ALL}\n")
        scan(url, templates, output_file=output_file, strict=strict)

if __name__ == "__main__":
    main()