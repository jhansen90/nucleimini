#!/usr/bin/env python3
import requests
import argparse
import sys
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

headers = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Termux) SubFinder/2.2"
}

# ==================== WORDLIST BAWAAN ====================
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www1", "intranet", "portal", "video",
    "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search",
    "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1", "sites",
    "proxy", "ads", "online", "crm", "cms", "backup", "mx2", "lyncdiscover", "info",
    "apps", "download", "remote", "db", "forums", "store", "relay", "files", "status",
    "office", "exchange", "smtp2", "app", "live", "owa", "en", "start", "sms",
    "newsletter", "ftp2", "ipv4", "mail3", "help", "blogs", "helpdesk", "web1",
    "home", "library", "ftp1", "gw", "gallery", "billing", "photos", "web2", "mx3",
    "stage", "s1", "tickets", "www4", "www5", "www6", "www7", "www8", "www9", "www10",
    "ns5", "ns6", "ns7", "ns8", "ns9", "ns10", "dns3", "dns4", "dns5", "smtp1",
    "smtp3", "smtp4", "pop1", "pop2", "imap1", "imap2", "mx4", "mx5", "mail4",
    "mail5", "web3", "web4", "web5", "cdn1", "cdn2", "cdn3", "static1", "static2",
    "img1", "img2", "img3", "api1", "api2", "api3", "dev1", "dev2", "test1", "test2",
    "staging1", "staging2", "beta1", "beta2", "uat", "qa", "sandbox", "demo1", "demo2",
    "prod", "production", "preprod", "preview", "alpha", "internal", "private",
    "corp", "corporate", "extranet", "partner", "partners", "client", "clients",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy", "monitor",
    "monitoring", "grafana", "prometheus", "kibana", "elasticsearch", "log", "logs",
    "dashboard", "panel", "control", "manage", "console", "ssh", "sftp", "vpn1",
    "vpn2", "rdp", "vnc", "cloud", "aws", "azure", "gcp", "s3", "storage", "cdn4",
    "cdn5", "edge", "cache", "nginx", "apache", "node", "python", "php", "java",
    "redis", "mongodb", "postgres", "mysql1", "mysql2", "db1", "db2", "database",
    "k8s", "kubernetes", "docker", "registry", "jira", "confluence", "sonar",
    "waf", "firewall", "ids", "ips", "siem", "helpdesk", "support1", "crm1",
    "erp", "lms", "moodle", "blog1", "forum1", "chat1", "video1", "stream",
    "mobile1", "m1", "amp", "api4", "rest", "graphql", "gateway", "proxy1",
    "lb", "backup1", "backup2", "old1", "old2", "temp", "tmp", "auth", "login",
    "sso", "oauth", "account", "accounts", "user", "users", "admin1", "admin2",
    "panel1", "cpanel1", "whm1", "plesk", "phpmyadmin", "pma", "webmail1",
    "mail6", "mail7", "mx6", "mx7", "ns11", "ns12", "dns6", "dns7", "resolver",
]

def banner():
    print(f"""{Fore.RED}
███████╗███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗
██╔════╝██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝
█████╗  ███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝ 
██╔══╝  ╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝  
██║     ███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║   
╚═╝     ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝   
{Fore.CYAN}
        Simple Subdomain Finder v2.2 - FarizalXploit
       Instagram: @farizal_dzaky_anazili
              [ fsociety ] + DNS Brute Force
    {Style.RESET_ALL}""")

def clean_domain(domain):
    domain = domain.lower().strip()
    if domain.startswith("http"):
        domain = domain.split("//")[-1].split("/")[0]
    domain = domain.split(":")[0].rstrip("/")
    return domain

def is_valid_subdomain(host, domain):
    host = host.lower().strip().rstrip(".")
    if not host or "*" in host or " " in host:
        return False
    if host == domain or host.endswith("." + domain):
        return True
    return False

def get_from_alienvault(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari AlienVault OTX ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = requests.get(url, headers=headers, timeout=25)
        if r.status_code == 200:
            data = r.json()
            for item in data.get("passive_dns", []):
                hostname = item.get("hostname", "")
                if is_valid_subdomain(hostname, domain):
                    subs.add(hostname.lower().rstrip("."))
            print(f"{Fore.GREEN}[+] AlienVault: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] AlienVault status {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] AlienVault gagal: {e}{Style.RESET_ALL}")
    return subs

def get_from_hackertarget(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari HackerTarget ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if is_valid_subdomain(sub, domain):
                        subs.add(sub.lower().rstrip("."))
            print(f"{Fore.GREEN}[+] HackerTarget: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] HackerTarget limit / error{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] HackerTarget gagal: {e}{Style.RESET_ALL}")
    return subs

def get_from_crtsh(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari crt.sh ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, headers=headers, timeout=40)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower().rstrip(".")
                    if is_valid_subdomain(sub, domain):
                        subs.add(sub)
            print(f"{Fore.GREEN}[+] crt.sh: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] crt.sh status {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] crt.sh gagal: {e}{Style.RESET_ALL}")
    return subs

def get_from_urlscan(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari urlscan.io ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            for result in data.get("results", []):
                page = result.get("page", {})
                host = page.get("domain", "") or page.get("apexDomain", "")
                if is_valid_subdomain(host, domain):
                    subs.add(host.lower().rstrip("."))
                task = result.get("task", {})
                task_domain = task.get("domain", "")
                if is_valid_subdomain(task_domain, domain):
                    subs.add(task_domain.lower().rstrip("."))
            print(f"{Fore.GREEN}[+] urlscan.io: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] urlscan status {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] urlscan gagal: {e}{Style.RESET_ALL}")
    return subs

def get_from_rapiddns(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari RapidDNS ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
        r = requests.get(url, headers=headers, timeout=25)
        if r.status_code == 200:
            found = re.findall(rf'(?:[\w\-]+\.)+{re.escape(domain)}', r.text, re.I)
            for sub in found:
                sub = sub.lower().rstrip(".")
                if is_valid_subdomain(sub, domain):
                    subs.add(sub)
            print(f"{Fore.GREEN}[+] RapidDNS: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] RapidDNS status {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] RapidDNS gagal: {e}{Style.RESET_ALL}")
    return subs

def get_from_threatcrowd(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari ThreatCrowd ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            for sub in data.get("subdomains", []):
                if is_valid_subdomain(sub, domain):
                    subs.add(sub.lower().rstrip("."))
            print(f"{Fore.GREEN}[+] ThreatCrowd: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] ThreatCrowd status {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] ThreatCrowd gagal: {e}{Style.RESET_ALL}")
    return subs

def get_from_bufferover(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari BufferOver ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            for key in ["FDNS_A", "RDNS"]:
                for item in data.get(key, []) or []:
                    parts = item.split(",")
                    host = parts[1].strip() if len(parts) >= 2 else item.strip()
                    if is_valid_subdomain(host, domain):
                        subs.add(host.lower().rstrip("."))
            print(f"{Fore.GREEN}[+] BufferOver: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] BufferOver status {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] BufferOver gagal: {e}{Style.RESET_ALL}")
    return subs

def get_from_certspotter(domain):
    print(f"{Fore.BLUE}[*] Mengambil dari CertSpotter ...{Style.RESET_ALL}")
    subs = set()
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        r = requests.get(url, headers=headers, timeout=25)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                for name in entry.get("dns_names", []):
                    if is_valid_subdomain(name, domain):
                        subs.add(name.lower().rstrip("."))
            print(f"{Fore.GREEN}[+] CertSpotter: {len(subs)} ditemukan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] CertSpotter status {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] CertSpotter gagal: {e}{Style.RESET_ALL}")
    return subs

# ==================== DNS BRUTE FORCE ====================
def resolve_dns(subdomain):
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(subdomain)
        return subdomain
    except (socket.gaierror, socket.timeout, OSError):
        return None

def load_wordlist(wordlist_path):
    words = set()
    if wordlist_path and os.path.isfile(wordlist_path):
        print(f"{Fore.CYAN}[*] Memuat wordlist dari: {wordlist_path}{Style.RESET_ALL}")
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip().lower()
                    if word and not word.startswith("#") and " " not in word:
                        words.add(word)
            print(f"{Fore.GREEN}[+] Wordlist custom: {len(words)} kata{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Gagal load wordlist: {e}, pakai default{Style.RESET_ALL}")
            words = set(DEFAULT_WORDLIST)
    else:
        words = set(DEFAULT_WORDLIST)
        print(f"{Fore.CYAN}[*] Menggunakan wordlist bawaan: {len(words)} kata{Style.RESET_ALL}")
    return sorted(words)

def dns_bruteforce(domain, wordlist, threads=50):
    print(f"\n{Fore.MAGENTA}[*] Memulai DNS Brute Force ...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Target     : {domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Wordlist   : {len(wordlist)} kata{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Threads    : {threads}{Style.RESET_ALL}\n")

    found = set()
    candidates = [f"{word}.{domain}" for word in wordlist]
    total = len(candidates)
    checked = 0
    last_print = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_dns, sub): sub for sub in candidates}
        for future in as_completed(futures):
            checked += 1
            result = future.result()
            if result:
                found.add(result)
                print(f"{Fore.GREEN}[+] Ditemukan : {result}{Style.RESET_ALL}")

            progress = int((checked / total) * 100)
            if progress >= last_print + 10 or checked % 100 == 0:
                print(f"{Fore.BLUE}[*] Progress  : {checked}/{total} ({progress}%) | Ditemukan: {len(found)}{Style.RESET_ALL}")
                last_print = progress

    print(f"\n{Fore.GREEN}[+] DNS Brute Force selesai: {len(found)} subdomain ditemukan{Style.RESET_ALL}")
    return found

def save_results(subdomains, output_file):
    sorted_subs = sorted(subdomains)
    with open(output_file, "w", encoding="utf-8") as f:
        for sub in sorted_subs:
            f.write(f"https://{sub}\n")
    print(f"\n{Fore.GREEN}[✓] Hasil disimpan ke → {output_file}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Total subdomain unik: {len(sorted_subs)}{Style.RESET_ALL}")

def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Subdomain Finder v2.2 + DNS Brute Force",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python3 subfinder.py example.com
  python3 subfinder.py example.com -b
  python3 subfinder.py example.com -b -w wordlist.txt
  python3 subfinder.py example.com -b -w wordlist.txt -bt 100 -o hasil.txt
        """
    )
    parser.add_argument("domain", help="Domain target (contoh: example.com)")
    parser.add_argument("-o", "--output", default="subdomains.txt", help="File output")
    parser.add_argument("-t", "--threads", type=int, default=8, help="Thread passive sources (default: 8)")
    parser.add_argument("-b", "--brute", action="store_true", help="Aktifkan DNS Brute Force")
    parser.add_argument("-w", "--wordlist", help="Path custom wordlist")
    parser.add_argument("-bt", "--brute-threads", type=int, default=50, help="Thread DNS Brute (default: 50)")
    args = parser.parse_args()

    domain = clean_domain(args.domain)
    print(f"{Fore.CYAN}[*] Target Domain : {domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Output File   : {args.output}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Threads       : {args.threads}{Style.RESET_ALL}")
    if args.brute:
        print(f"{Fore.CYAN}[*] DNS Brute     : Aktif (threads: {args.brute_threads}){Style.RESET_ALL}")
    print()

    all_subs = set()

    sources = [
        get_from_alienvault,
        get_from_hackertarget,
        get_from_crtsh,
        get_from_urlscan,
        get_from_rapiddns,
        get_from_threatcrowd,
        get_from_bufferover,
        get_from_certspotter,
    ]

    print(f"{Fore.YELLOW}========== PASSIVE ENUMERATION =========={Style.RESET_ALL}\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(func, domain): func.__name__ for func in sources}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                all_subs.update(result)
            except Exception as e:
                print(f"{Fore.RED}[!] Error di {name}: {e}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[✓] Passive selesai: {len(all_subs)} subdomain unik{Style.RESET_ALL}")

    if args.brute:
        print(f"\n{Fore.YELLOW}========== DNS BRUTE FORCE =========={Style.RESET_ALL}")
        wordlist = load_wordlist(args.wordlist)
        brute_found = dns_bruteforce(domain, wordlist, threads=args.brute_threads)
        all_subs.update(brute_found)

    all_subs.add(domain)

    if not all_subs:
        print(f"\n{Fore.RED}[!] Tidak ada subdomain yang ditemukan.{Style.RESET_ALL}")
        return

    save_results(all_subs, args.output)

    print(f"\n{Fore.YELLOW}--- Preview (20 pertama) ---{Style.RESET_ALL}")
    for sub in sorted(all_subs)[:20]:
        print(f"  https://{sub}")
    if len(all_subs) > 20:
        print(f"  ... dan {len(all_subs)-20} lainnya")

if __name__ == "__main__":
    main()