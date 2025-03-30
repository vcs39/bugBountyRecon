import os
import subprocess
import argparse
import shutil
from datetime import datetime
from colorama import Fore, Style, init


# VS Code Python environment note:
# To start a Python environment in VS Code:
# 1. Press Ctrl+Shift+P and type "Python: Create Environment" or "Python: Select Interpreter"
# 2. Choose a virtual environment or existing interpreter.
# 3. Use the terminal to activate:
#    - On Linux/macOS: source .venv/bin/activate
#    - On Windows: .venv\Scripts\activate
# 4. Run this script: python3 script_name.py -d target.com


def print_banner():
    ascii_banner = r"""
 __     ___      _                    ____      _               
 \ \   / (_) ___(_) ___  _   _ ___   / ___|   _| |__   ___ _ __ 
  \ \ / /| |/ __| |/ _ \| | | / __| | |  | | | | '_ \ / _ \ '__|
   \ V / | | (__| | (_) | |_| \__ \ | |__| |_| | |_) |  __/ |   
    \_/  |_|\___|_|\___/ \__,_|___/  \____\__, |_.__/ \___|_|   
                                          |___/                 

 ____        _       _   _                 
/ ___|  ___ | |_   _| |_(_) ___  _ __  ___ 
\___ \ / _ \| | | | | __| |/ _ \| '_ \/ __|
 ___) | (_) | | |_| | |_| | (_) | | | \__ \
|____/ \___/|_|\__,_|\__|_|\___/|_| |_|___/
    """
    print(ascii_banner)
    print("\U0001F512 Vicious Cyber Solutions \U0001F512")


init(autoreset=True)

OUTPUT_DIR = "bugbounty_output"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
TARGET_DIR = os.path.join(OUTPUT_DIR, TIMESTAMP)
os.makedirs(TARGET_DIR, exist_ok=True)
print(Fore.GREEN + f"[DEBUG] Created target directory: {TARGET_DIR}")


def run_command(command, output_file=None):
    print(Fore.CYAN + f"[RUNNING] {command}")
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
        if output_file:
            with open(os.path.join(TARGET_DIR, output_file), "w") as f:
                f.write(result.stdout)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[ERROR] Command failed: {command}\n{e.stderr.strip()}")
        return ""
    except Exception as e:
        print(Fore.RED + f"[EXCEPTION] {str(e)}")
        return ""


def check_tools():
    tools = [
        "amass", "subfinder", "assetfinder", "httprobe", "aquatone",
        "nmap", "ffuf", "hakrawler", "paramspider", "whatweb",
        "linkfinder.py", "sslscan"
    ]
    missing = []
    for tool in tools:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        print(Fore.YELLOW + f"[!] Warning: Missing tools: {', '.join(missing)}. Please install them before proceeding.")


def recon_wildcard(domain):
    print(Fore.GREEN + "\n[*] Starting wildcard subdomain recon...")

    run_command(f"amass enum -d {domain}", "amass.txt")
    run_command(f"subfinder -d {domain}", "subfinder.txt")
    run_command(f"assetfinder --subs-only {domain}", "assetfinder.txt")

    print(Fore.GREEN + "[*] Merging and deduplicating results...")
    run_command(f"sort -u {TARGET_DIR}/amass.txt {TARGET_DIR}/subfinder.txt {TARGET_DIR}/assetfinder.txt > {TARGET_DIR}/subdomains.txt")

    run_command(f"cat {TARGET_DIR}/subdomains.txt | httprobe > {TARGET_DIR}/alive_subdomains.txt")
    run_command(f"cat {TARGET_DIR}/alive_subdomains.txt | aquatone")
    print(Fore.GREEN + "[*] Wildcard recon completed!")


def single_domain_scan(domain):
    print(Fore.GREEN + "\n[*] Starting single domain scan...")
    run_command(f"nmap -A -T4 {domain}", "nmap_scan.txt")
    run_command(f"ffuf -u https://{domain}/FUZZ -w /usr/share/wordlists/dirb/common.txt -o {TARGET_DIR}/ffuf_output.txt")
    run_command(f"hakrawler -url {domain} -depth 2 -plain", "hakrawler.txt")
    run_command(f"paramspider --domain {domain}", "paramspider.txt")
    run_command(f"whatweb {domain}", "whatweb.txt")
    run_command(f"sslscan {domain}", "sslscan.txt")
    run_command(f"python3 linkfinder.py -i https://{domain} -o {TARGET_DIR}/linkfinder_output.html")
    print(Fore.GREEN + "[*] Single domain scan completed!")

    print(Fore.MAGENTA + "\n[*] Google Dork Suggestions:")
    dorks = [
        f"site:{domain} filetype:pdf",
        f"site:{domain} inurl:admin",
        f"site:{domain} intitle:index of",
        f"site:{domain} ext:sql | ext:txt | ext:log"
    ]
    for dork in dorks:
        print(Fore.YELLOW + f" - {dork}")


def generate_html_report():
    index_path = os.path.join(TARGET_DIR, "report.html")
    with open(index_path, "w") as f:
        f.write("<html><head><title>Bug Bounty Recon Report</title></head><body>")
        f.write("<h1>Recon Results</h1>")
        for file in os.listdir(TARGET_DIR):
            if file.endswith(".txt") or file.endswith(".html"):
                f.write(f"<h2>{file}</h2><pre>")
                with open(os.path.join(TARGET_DIR, file), "r") as content:
                    f.write(content.read())
                f.write("</pre><hr>")
        f.write("</body></html>")
    print(Fore.CYAN + f"\n[+] HTML report generated at: {index_path}")


def main():
    parser = argparse.ArgumentParser(description="Advanced Bug Bounty Recon Automation", allow_abbrev=False)
    parser.add_argument("-d", "--domain", required=False, help="Target domain", default="testphp.vulnweb.com")
    args = parser.parse_args()

    print_banner()
    check_tools()
    print(Fore.CYAN + f"\n[+] Starting Recon for: {args.domain}")
    recon_wildcard(args.domain)
    single_domain_scan(args.domain)
    generate_html_report()
    print(Fore.CYAN + f"\n[+] Recon complete. Results saved in {TARGET_DIR}")


if __name__ == "__main__":
    main()
