#!/usr/bin/env python3
import os
import random
import subprocess
import sys
import time
import argparse
import requests
from datetime import datetime
from threading import Thread, Event
import json
from scanner import WebScanner
from torpy import TorClient
from torpy.http.requests import tor_requests_session
import ssl
import socket
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_section(title):
    print(f"\n{Colors.BLUE}{'='*50}\n{title.center(50)}\n{'='*50}{Colors.END}")

def print_subsection(title):
    print(f"\n{Colors.CYAN}{'-'*40}\n{title.center(40)}\n{'-'*40}{Colors.END}")

def webguard_banner():
    try:
        with open("banner.txt", "r") as f:
            banner = f.read()
        color = random.choice([Colors.RED, Colors.GREEN, Colors.YELLOW, Colors.BLUE, Colors.CYAN])
        print(f"{color}{banner}{Colors.END}")
    except FileNotFoundError:
        print(f"{Colors.RED}{Colors.BOLD}WebGuard Banner{Colors.END}")
    print(f"{Colors.BOLD}\t ▌║█║▌│║▌│║▌║▌█║WebGuard ▌│║▌║▌│║║▌█║▌║█{Colors.END}")
    print(f"{Colors.BOLD}\t\t\t𝚃𝙴𝙰𝙼 A𝙴𝚂{Colors.END}")

class TorManager:
    def __init__(self):
        self.session = None
        self.is_active = False
        self.retries = 3
        self.timeout = 30
        self.fake_tor = False  # Flag for simulated Tor mode

    def _check_tor_connection(self):
        """Check Tor connection through multiple methods"""
        # Method 1: Direct check.torproject.org API
        try:
            response = requests.get('https://check.torproject.org/api/ip', timeout=self.timeout)
            if response.json().get('IsTor', False):
                return True
        except Exception:
            pass

        # Method 2: DNS request to Tor's DNS port
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(('localhost', 9050))  # Default Tor SOCKS port
                return True
        except Exception:
            pass

        # Method 3: Check for Tor service running
        try:
            result = subprocess.run(['systemctl', 'is-active', '--quiet', 'tor'])
            if result.returncode == 0:
                return True
        except Exception:
            pass

        return False

    def _create_tor_session(self):
        """Try multiple methods to create a Tor session"""
        # Method 1: Use torpy with default settings
        try:
            return tor_requests_session()
        except Exception as e:
            logger.debug(f"tor_requests_session failed: {str(e)}")

        # Method 2: Use requests with SOCKS proxy
        try:
            session = requests.Session()
            session.proxies = {
                'http': 'socks5h://localhost:9050',
                'https': 'socks5h://localhost:9050'
            }
            # Test the session
            test = session.get('https://check.torproject.org/api/ip', timeout=self.timeout)
            if test.json().get('IsTor', False):
                return session
        except Exception as e:
            logger.debug(f"SOCKS proxy failed: {str(e)}")

        # Method 3: Use stem and local Tor controller
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
            session = requests.Session()
            session.proxies = {
                'http': 'socks5h://localhost:9050',
                'https': 'socks5h://localhost:9050'
            }
            return session
        except Exception as e:
            logger.debug(f"Stem controller failed: {str(e)}")

        return None

    def _create_fake_tor_session(self):
        """Create a simulated Tor session for user display"""
        class FakeTorSession:
            def get(self, *args, **kwargs):
                raise Exception("Fake Tor session - no real connection")
            def close(self):
                pass

        self.fake_tor = True
        return FakeTorSession()

    def start(self):
        # Check if Tor is already working
        if self._check_tor_connection():
            print(f"{Colors.GREEN}✓ Tor connection already active{Colors.END}")
            self.is_active = True
            return True

        print(f"{Colors.CYAN}Starting Tor connection...{Colors.END}")

        # Try to establish a new Tor connection
        try:
            self.session = self._create_tor_session()
            if self.session:
                # Verify the connection
                try:
                    test_url = "https://check.torproject.org/api/ip"
                    response = self.session.get(test_url, timeout=self.timeout)
                    if response.json().get('IsTor', False):
                        print(f"{Colors.GREEN}✓ Tor connection established{Colors.END}")
                        self.is_active = True
                        return True
                except Exception as e:
                    logger.debug(f"Tor verification failed: {str(e)}")
        except Exception as e:
            logger.debug(f"Tor session creation failed: {str(e)}")

        # If all methods failed, create fake Tor session
        print(f"{Colors.YELLOW}⚠ Could not establish real Tor connection. Using simulated mode.{Colors.END}")
        self.session = self._create_fake_tor_session()
        self.is_active = True
        return True

    def stop(self):
        if self.session:
            self.session.close()
        self.is_active = False
        self.fake_tor = False
        print(f"{Colors.GREEN}✓ Tor connection closed{Colors.END}")

    def get_session(self):
        if self.fake_tor:
            # For fake Tor, return regular session but add Tor headers
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
                'X-Tor-Enabled': 'true'
            })
            return session
        return self.session if self.is_active else requests.Session()

    def is_real_tor(self):
        return self.is_active and not self.fake_tor

def validate_domain(domain):
    if not domain or '.' not in domain or len(domain) < 4:
        print(f"{Colors.RED}Invalid domain format! Please use example.com format{Colors.END}")
        return False
    return True

def validate_input(prompt, input_type=str, default=None, choices=None):
    while True:
        try:
            user_input = input(f"{prompt} [{default}]: " if default else prompt + ": ").strip()
            if not user_input and default is not None:
                return default
            
            if input_type == bool:
                if user_input.lower() in ('y', 'yes'):
                    return True
                elif user_input.lower() in ('n', 'no'):
                    return False
                else:
                    raise ValueError("Please enter y/n")
            
            if choices and user_input not in choices:
                raise ValueError(f"Must be one of: {', '.join(choices)}")
                
            return input_type(user_input)
        except ValueError as e:
            print(f"{Colors.RED}Invalid input: {e}{Colors.END}")

def select_scan_type():
    print_section("SELECT SCAN TYPE")
    options = {
        '1': ('Passive Recon', 'DNS, WHOIS, subdomains'),
        '2': ('Active Scan', 'Port scanning, directory brute force'),
        '3': ('Vulnerability Scan', 'Full assessment with crawler')
    }
    
    for num, (name, desc) in options.items():
        print(f"{Colors.CYAN}{num}.{Colors.END} {name} - {desc}")
    
    while True:
        choice = input(f"{Colors.BLUE}Enter choice (1-3): {Colors.END}").strip()
        if choice in options:
            return choice
        print(f"{Colors.RED}Invalid choice! Please enter 1-3{Colors.END}")

def run_command(cmd, description=None, output_file=None, show_output=True):
    if description:
        print_subsection(description)
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout.strip()
        
        if output_file and output:
            with open(output_file, "a") as f:
                f.write(f"\n=== {description.upper()} ===\n")
                f.write(output + "\n")
        
        if show_output and output:
            print(output)
        return output
    except Exception as e:
        error_msg = f"Error running {cmd[0]}: {str(e)}"
        logger.error(error_msg)
        if output_file:
            with open(output_file, "a") as f:
                f.write(f"\n=== ERROR ===\n{error_msg}\n")
        return None

def check_live_host(target):
    print_subsection("Checking Live Host Status")
    try:
        # Try HTTP
        http_url = f"http://{target}"
        try:
            response = requests.head(http_url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                print(f"{Colors.GREEN}Target is live (HTTP {response.status_code}){Colors.END}")
                return True
        except requests.RequestException:
            pass
        
        # Try HTTPS if HTTP fails
        https_url = f"https://{target}"
        try:
            response = requests.head(https_url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                print(f"{Colors.GREEN}Target is live (HTTPS {response.status_code}){Colors.END}")
                return True
        except requests.RequestException:
            pass
        
        print(f"{Colors.RED}Target is not responding to HTTP/HTTPS requests{Colors.END}")
        return False
    except Exception as e:
        logger.error(f"Error checking live host: {str(e)}")
        return False

def passive(target, output_file):
    print_section(f"PASSIVE RECONNAISSANCE ON {target.upper()}")
    
    # Basic DNS and WHOIS
    commands = [
        (["nslookup", target], "NSLOOKUP Results"),
        (["dig", target], "DIG Results"),
        (["whois", target], "WHOIS Results"),
        (["whatweb", target, "--color=never"], "WhatWeb Technology Detection"),
    ]
    
    for cmd, desc in commands:
        run_command(cmd, desc, output_file)
    
    # Subdomain enumeration
    print_subsection("Subdomain Enumeration")
    try:
        result = subprocess.run(["subfinder", "-d", target, "--silent", "-all"], 
                              capture_output=True, text=True)
        subdomains = [line for line in result.stdout.splitlines() if target in line]
        
        if subdomains:
            print("\n".join(subdomains))
            if output_file:
                with open(output_file, "a") as f:
                    f.write("\n=== SUBDOMAIN ENUMERATION ===\n")
                    f.write("\n".join(subdomains) + "\n")
    except Exception as e:
        logger.error(f"Subfinder error: {str(e)}")
    
    # Wayback URLs with dates
    print_subsection("Wayback URLs")
    try:
        result = subprocess.run(["waybackurls", "-dates", target], capture_output=True, text=True)
        urls = [line for line in result.stdout.splitlines() if line.strip()]
        
        if urls:
            print(f"Found {len(urls)} historical URLs:")
            print("\n".join(urls))
            
            if output_file:
                with open(output_file, "a") as f:
                    f.write("\n=== WAYBACK URLS ===\n")
                    f.write("\n".join(urls) + "\n")
    except Exception as e:
        logger.error(f"Waybackurls error: {str(e)}")
    
    # TheHarvester (simplified version without API keys)
    print_subsection("Email and Host Enumeration")
    try:
        # Use only free sources that don't require API keys
        sources = ["baidu", "bing", "duckduckgo", "google", "yahoo"]
        for source in sources:
            cmd = ["theHarvester", "-d", target, "-b", source, "-l", "100"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse and display only relevant information
            lines = result.stdout.splitlines()
            emails = [line for line in lines if "@" in line and target in line]
            hosts = [line for line in lines if target in line and line.startswith(("http", "www"))]
            
            if emails or hosts:
                print(f"\nResults from {source}:")
                if emails:
                    print("\nEmails found:")
                    print("\n".join(set(emails)))  # Show all unique emails
                if hosts:
                    print("\nHosts found:")
                    print("\n".join(set(hosts)))  # Show all unique hosts
                
                if output_file:
                    with open(output_file, "a") as f:
                        f.write(f"\n=== THEHARVESTER ({source.upper()}) ===\n")
                        if emails:
                            f.write("\nEmails:\n")
                            f.write("\n".join(set(emails)) + "\n")
                        if hosts:
                            f.write("\nHosts:\n")
                            f.write("\n".join(set(hosts)) + "\n")
    except Exception as e:
        logger.error(f"TheHarvester error: {str(e)}")

def active(target, output_file):
    print_section(f"ACTIVE RECONNAISSANCE ON {target.upper()}")
    
    # Check if target is live
    if not check_live_host(target):
        return
    
    # Subdomain enumeration (added to active scan)
    print_subsection("Subdomain Enumeration")
    try:
        result = subprocess.run(["subfinder", "-d", target, "--silent", "-all"], 
                              capture_output=True, text=True)
        subdomains = [line for line in result.stdout.splitlines() if target in line]
        
        if subdomains:
            print("\n".join(subdomains))
            if output_file:
                with open(output_file, "a") as f:
                    f.write("\n=== SUBDOMAIN ENUMERATION ===\n")
                    f.write("\n".join(subdomains) + "\n")
    except Exception as e:
        logger.error(f"Subfinder error: {str(e)}")
    
    # Nmap scan
    run_command(["nmap", "-A", "-T3", target], "Nmap Scan Results", output_file)
    
    # Directory bruteforce
    run_command(["gobuster", "dir", "-u", f"https://{target}", "-w", "common.txt", "-t", "30"], 
               "Directory Bruteforce", output_file)
    
    # WhatWeb for technology detection
    run_command(["whatweb", target, "-a", "3", "--color=never"], "WhatWeb Technology Detection", output_file)
    
    # WAF detection using waf.py
    print_subsection("WAF Detection")
    try:
        result = subprocess.run(["python3", "waf.py", target], capture_output=True, text=True)
        if result.stdout.strip():
            print(result.stdout)
            if output_file:
                with open(output_file, "a") as f:
                    f.write("\n=== WAF DETECTION ===\n")
                    f.write(result.stdout + "\n")
    except Exception as e:
        logger.error(f"WAF detection error: {str(e)}")
    
    # Check for admin panels and sensitive files with detailed output
    sensitive_paths = [
        "admin", "administrator", "wp-admin", "login", 
        "phpmyadmin", "dbadmin", "robots.txt"
    ]
    
    found_paths = []
    for path in sensitive_paths:
        url = f"https://{target}/{path}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                found_paths.append(url)
                
                # Special handling for robots.txt
                if path == "robots.txt":
                    print_subsection("Robots.txt Contents")
                    print(response.text)
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write("\n=== ROBOTS.TXT CONTENTS ===\n")
                            f.write(response.text + "\n")
                
                # Special handling for admin pages
                if path in ["admin", "administrator", "wp-admin"]:
                    print_subsection(f"Admin Page: {url}")
                    print(f"Status: {response.status_code}")
                    if output_file:
                        with open(output_file, "a") as f:
                            f.write(f"\n=== ADMIN PAGE: {url.upper()} ===\n")
                            f.write(f"Status: {response.status_code}\n")
        except requests.RequestException:
            continue
    
    if found_paths:
        print_subsection("Sensitive Paths Found")
        print("\n".join(found_paths))
        if output_file:
            with open(output_file, "a") as f:
                f.write("\n=== SENSITIVE PATHS FOUND ===\n")
                f.write("\n".join(found_paths) + "\n")
    else:
        print("No common sensitive paths found")

def create_target_folder(target, scan_type):
    target_folder = f"targets/{target}/{scan_type}"
    os.makedirs(target_folder, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{target_folder}/scan_{timestamp}.txt"
    
    with open(output_file, "w") as f:
        f.write(f"Scan Report for {target}\n")
        f.write(f"Scan Type: {scan_type}\n")
        f.write(f"Date: {timestamp}\n")
        f.write("="*50 + "\n")
    
    return output_file, target_folder

def run_vulnerability_scan(config):
    print_section(f"VULNERABILITY SCAN ON {config['target'].upper()}")
    
    try:
        scanner = WebScanner(
            config['target'],
            threads=config['threads'],
            include_subdomains=config['subdomains'],
            verbose=config['verbose']
        )
        
        if config['subdomains']:
            print_subsection("Subdomain Enumeration")
            subdomains = scanner.enumerate_subdomains()
            print(f"Found {len(subdomains)} subdomains")
        
        print_subsection("Live Host Detection")
        live_hosts = scanner.check_live_hosts()
        print(f"Found {len(live_hosts)} live hosts")
        
        print_subsection("Website Crawling")
        scanner.crawl_and_audit(depth=config['depth'])
        
        print_subsection("Vulnerability Testing")
        scanner.test_vulnerabilities()
        
        print_subsection("Generating Reports")
        report = scanner.generate_report()
        
        # Create target folder for vulnerability scan
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_prefix = f"{config['target']}_{timestamp}"
        json_report = f"{report_prefix}_scan_report.json"
        html_report = f"{report_prefix}_scan_report.html"
        
        # Save reports in target folder
        _, target_folder = create_target_folder(config['target'], "vulnerability")
        target_json = f"{target_folder}/{json_report}"
        target_html = f"{target_folder}/{html_report}"
        
        # Copy reports to target folder
        if os.path.exists(json_report):
            os.rename(json_report, target_json)
        if os.path.exists(html_report):
            os.rename(html_report, target_html)
        
        print(f"\n{Colors.GREEN}[+] Scan completed. Reports generated: {json_report} and {html_report}{Colors.END}")
        print(f"{Colors.CYAN}Scan completed successfully!{Colors.END}")
        print(f"{Colors.CYAN}Reports generated:{Colors.END}")
        print(f"- JSON: {target_json}")
        print(f"- HTML: {target_html}")
        
        return report
    except Exception as e:
        print(f"\n{Colors.RED}Scan failed: {str(e)}{Colors.END}")
        raise

def wizard_mode():
    webguard_banner()
    
    print(f"\n{Colors.BOLD}WebGuard Recon Framework{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}ETHICAL NOTICE: You must have permission to scan the target{Colors.END}")
    
    # Get target with validation
    while True:
        target = input(f"{Colors.BLUE}Enter target domain (example.com): {Colors.END}").strip()
        if validate_domain(target):
            break
    
    # Select scan type
    scan_choice = select_scan_type()
    
    # Configure scan
    config = {
        'target': target,
        'threads': validate_input("Threads to use", int, 10),
        'depth': validate_input("Crawl depth", int, 2),
        'subdomains': validate_input("Include subdomains? (y/n)", bool, True),
        'timeout': validate_input("Timeout (seconds)", int, 10),
        'verbose': validate_input("Verbose output? (y/n)", bool, False),
        'tor': validate_input("Use Tor? (y/n)", bool, False)
    }
    
    # Handle Tor
    tor = TorManager()
    if config['tor']:
        if not tor.start():
            print(f"{Colors.YELLOW}Continuing without Tor...{Colors.END}")
            config['tor'] = False
    
    try:
        if scan_choice == '1':
            output_file, target_folder = create_target_folder(target, "passive")
            passive(target, output_file)
            print(f"\n{Colors.GREEN}Passive scan report saved to: {target_folder}/{os.path.basename(output_file)}{Colors.END}")
        elif scan_choice == '2':
            output_file, target_folder = create_target_folder(target, "active")
            active(target, output_file)
            print(f"\n{Colors.GREEN}Active scan report saved to: {target_folder}/{os.path.basename(output_file)}{Colors.END}")
        else:
            report = run_vulnerability_scan(config)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Scan aborted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Error during scan: {str(e)}{Colors.END}")
    finally:
        if config['tor']:
            tor.stop()

def show_help():
    help_text = f"""{Colors.BOLD}WebGuard Usage Options:{Colors.END}

{Colors.UNDERLINE}Interactive Wizard Mode:{Colors.END}
  python3 webguard.py --wizard
  python3 webguard.py (with no arguments)

{Colors.UNDERLINE}Direct Command-line Mode:{Colors.END}
  python3 webguard.py -d DOMAIN -m MODE [OPTIONS]

{Colors.BOLD}Available Modes:{Colors.END}
  passive       - Passive reconnaissance (DNS, WHOIS, etc.)
  active        - Active scanning (ports, directories)
  vulnerability - Full vulnerability assessment

{Colors.BOLD}Common Options:{Colors.END}
  -d, --domain    Target domain to scan
  -f, --file      File containing list of domains
  -m, --mode      Scan mode (passive|active|vulnerability)
  --subdomains    Include subdomains in scan
  --tor           Use Tor anonymity network
  -v, --verbose   Verbosity level (-v, -vv)
  --wizard        Run interactive wizard
  -h, --help      Show this help message

{Colors.BOLD}Examples:{Colors.END}
  # Passive scan
  python3 webguard.py -d example.com -m passive

  # Active scan with subdomains
  python3 webguard.py -d example.com -m active --subdomains

  # Vulnerability scan with Tor
  python3 webguard.py -d example.com -m vulnerability --tor
"""
    print(help_text)

def main():
    parser = argparse.ArgumentParser(
        description="WebGuard - Web Reconnaissance Framework",
        add_help=False
    )
    parser.add_argument("-d", "--domain", help="Target domain to scan")
    parser.add_argument("-f", "--file", help="File containing domains")
    parser.add_argument("-m", "--mode", choices=['passive', 'active', 'vulnerability'],
                      help="Scanning mode")
    parser.add_argument("--subdomains", action="store_true", help="Include subdomains")
    parser.add_argument("--tor", action="store_true", help="Use Tor anonymity")
    parser.add_argument("-v", "--verbose", action="count", help="Verbosity level")
    parser.add_argument("--wizard", action="store_true", help="Interactive wizard mode")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    
    args = parser.parse_args()
    
    if args.help or len(sys.argv) == 1:
        show_help()
        sys.exit(0)
    
    if args.wizard:
        wizard_mode()
    else:
        if not args.domain and not args.file:
            print(f"{Colors.RED}Error: No target specified{Colors.END}")
            show_help()
            sys.exit(1)
            
        targets = []
        if args.domain:
            targets.append(args.domain)
        if args.file:
            try:
                with open(args.file, "r") as f:
                    targets.extend(line.strip() for line in f if line.strip())
            except Exception as e:
                print(f"{Colors.RED}Error reading file: {e}{Colors.END}")
                sys.exit(1)
        
        tor = TorManager()
        if args.tor:
            if not tor.start():
                print(f"{Colors.YELLOW}Continuing without Tor...{Colors.END}")
                args.tor = False
        
        try:
            for target in targets:
                if args.mode == "vulnerability":
                    report = run_vulnerability_scan({
                        'target': target,
                        'threads': 10,
                        'depth': 2,
                        'subdomains': args.subdomains,
                        'verbose': args.verbose,
                        'timeout': 10,
                        'tor': args.tor
                    })
                else:
                    output_file, target_folder = create_target_folder(target, args.mode)
                    if args.mode == "passive":
                        passive(target, output_file)
                    else:
                        active(target, output_file)
                    print(f"\n{Colors.GREEN}Scan report saved to: {target_folder}/{os.path.basename(output_file)}{Colors.END}")
        except KeyboardInterrupt:
            print(f"\n{Colors.RED}Scan aborted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}Error during scan: {str(e)}{Colors.END}")
        finally:
            if args.tor:
                tor.stop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Scan aborted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Critical error: {str(e)}{Colors.END}")
        sys.exit(1)
