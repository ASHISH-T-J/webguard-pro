#!/usr/bin/env python3
import os
import random
import subprocess
import sys
import time
from datetime import datetime
from threading import Thread, Event

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

# Function to get a random color
def random_color():
    return random.randint(30, 37)

# Function to print text with dynamic color
def print_dynamic_color(text):
    color = random_color()
    print(f"\033[1;{color}m{text}\033[0m")

# Function to display the webguard banner
def webguard_banner():
    try:
        with open("banner.txt", "r") as f:
            banner = f.read()
        print(f"\033[1;{random_color()}m{banner}\033[0m")
    except FileNotFoundError:
        print_dynamic_color("WebGuard Banner")
    print_dynamic_color("\t ▌║█║▌│║▌│║▌║▌█║WebGuard ▌│║▌║▌│║║▌█║▌║█")
    print_dynamic_color("\t\t\t𝚃𝙴𝙰𝙼 A𝙴𝚂")

# Function for loading effect
def loading_effect(stop_event):
    loading_text = "Loading...!!!!"
    loading_animation = "⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
    
    while not stop_event.is_set():
        for i in range(len(loading_text)):
            if stop_event.is_set():
                break
            print(f"\033[1;{random_color()}m{loading_animation[i]}\033[0m", end='', flush=True)
            time.sleep(0.1)
        print("\r\033[K", end='', flush=True)

# Function to perform subdomain enumeration
def subdomain(target, output_file):
    print(f"{Colors.BLUE}{Colors.BOLD}PERFORMING SUBDOMAIN ENUMERATION ON {target.upper()}{Colors.END}", flush=True)
    with open(output_file, "a") as f:
        f.write(f"=== SUBDOMAIN ENUMERATION ON {target.upper()} ===\n")
    
    try:
        result = subprocess.run(["subfinder", "-d", target, "--silent", "-all"], capture_output=True, text=True)
        subdomains = [line for line in result.stdout.splitlines() if target in line]
        
        with open("sublist.txt", "w") as f:
            f.write("\n".join(subdomains))
        
        with open(output_file, "a") as f:
            f.write("\n".join(subdomains) + "\n")
        
        print("\n".join(subdomains))
    except Exception as e:
        print(f"{Colors.RED}Error during subdomain enumeration: {e}{Colors.END}")

# Function to perform passive reconnaissance
def passive(target, output_file):
    print(f"{Colors.BLUE}{Colors.BOLD}PERFORMING PASSIVE RECONNAISSANCE...{Colors.END}", flush=True)
    time.sleep(2)
    
    with open(output_file, "a") as f:
        f.write("\n=== PASSIVE RECONNAISSANCE ===\n")
        
        # NSLOOKUP
        f.write("\n--- NSLOOKUP Results ---\n")
        try:
            nslookup = subprocess.run(["nslookup", target], capture_output=True, text=True)
            nslookup_results = [line for line in nslookup.stdout.splitlines() if "Address:" in line]
            f.write("\n".join(nslookup_results) + "\n")
            print("\n".join(nslookup_results))
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}NSLOOKUP Error: {e}{Colors.END}")
        
        # DIG
        f.write("\n--- DIG Results ---\n")
        try:
            dig = subprocess.run(["dig", target], capture_output=True, text=True)
            dig_results = [line for line in dig.stdout.splitlines() if "ANSWER SECTION" in line]
            f.write("\n".join(dig_results) + "\n")
            print("\n".join(dig_results))
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}DIG Error: {e}{Colors.END}")
        
        # WhatWeb
        f.write("\n--- WhatWeb Results ---\n")
        try:
            whatweb = subprocess.run(["whatweb", target], capture_output=True, text=True)
            f.write(whatweb.stdout + "\n")
            print(whatweb.stdout)
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}WhatWeb Error: {e}{Colors.END}")
        
        # WHOIS
        f.write("\n--- WHOIS Results ---\n")
        try:
            whois = subprocess.run(["whois", target], capture_output=True, text=True)
            whois_results = [line for line in whois.stdout.splitlines() if "Registrant" in line or "Registrar" in line]
            f.write("\n".join(whois_results) + "\n")
            print("\n".join(whois_results))
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}WHOIS Error: {e}{Colors.END}")
        
        # Subdomain Enumeration
        subdomain(target, output_file)
        
        # Wayback URLs
        print(f"{Colors.BLUE}{Colors.BOLD}GATHERING PUBLIC ARCHIVES...{Colors.END}", flush=True)
        f.write("\n--- Wayback URLs Results ---\n")
        try:
            wayback = subprocess.run(["waybackurls", "-dates", "-get-versions", target], capture_output=True, text=True)
            f.write(wayback.stdout + "\n")
            print(wayback.stdout)
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}Wayback Error: {e}{Colors.END}")
        
        # TheHarvester
        f.write("\n--- TheHarvester Results ---\n")
        try:
            theharvester = subprocess.run(["theHarvester", "-d", target, "-l", "100", "-b", "all"], capture_output=True, text=True)
            harvester_results = [line for line in theharvester.stdout.splitlines() if target in line]
            f.write("\n".join(harvester_results) + "\n")
            print("\n".join(harvester_results))
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}TheHarvester Error: {e}{Colors.END}")

# Function to perform directory enumeration
def directory_enum(url, output_file):
    print(f"{Colors.BLUE}{Colors.BOLD}PERFORMING DIRECTORY AND FILE ENUMERATION ON {url}{Colors.END}", flush=True)
    with open(output_file, "a") as f:
        f.write("\n=== DIRECTORY ENUMERATION ===\n")
    
    try:
        gobuster = subprocess.run(["gobuster", "dir", "-u", url, "-w", "common.txt", "-t", "30", "-q", "--no-error"], 
                                 capture_output=True, text=True)
        with open(output_file, "a") as f:
            f.write(gobuster.stdout + "\n")
        print(gobuster.stdout)
    except Exception as e:
        print(f"{Colors.RED}Directory enumeration error: {e}{Colors.END}")

# Function to scrape admin page, phpMyAdmin page, and robots.txt
def scrape(target_url, output_file):
    import requests
    found_result = False
    
    with open(output_file, "a") as f:
        f.write("\n=== ADMIN PANEL AND ROBOTS.TXT CHECK ===\n")
    
    # Function to highlight and print specific results
    def highlight_result(result):
        print(f"{Colors.RED}{Colors.BOLD}{result}{Colors.END}")
        with open(output_file, "a") as f:
            f.write(result + "\n")
    
    # Check robots.txt
    robots_url = f"{target_url.rstrip('/')}/robots.txt"
    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            highlight_result(f"Robots.txt entries from {robots_url}:")
            highlight_result(response.text)
            found_result = True
        else:
            print(f"No robots.txt found at {robots_url}.")
    except Exception as e:
        print(f"{Colors.RED}Error checking robots.txt: {e}{Colors.END}")
    
    # Check admin pages
    admin_pages = ["administrator", "admin", "admin/login", "admin/index.php", "administrator/index.php"]
    for admin_page in admin_pages:
        admin_url = f"{target_url.rstrip('/')}/{admin_page}"
        try:
            response = requests.get(admin_url)
            if response.status_code == 200:
                highlight_result(f"Admin page found: {admin_url}")
                found_result = True
                break
        except Exception as e:
            continue
    
    # Check phpMyAdmin pages
    phpmyadmin_pages = ["phpmyadmin", "pma", "phpMyAdmin", "phpmyadmin/index.php"]
    for phpmyadmin_page in phpmyadmin_pages:
        phpmyadmin_url = f"{target_url.rstrip('/')}/{phpmyadmin_page}"
        try:
            response = requests.get(phpmyadmin_url)
            if response.status_code == 200:
                highlight_result(f"phpMyAdmin page found: {phpmyadmin_url}")
                found_result = True
                break
        except Exception as e:
            continue
    
    if not found_result:
        print("No specific results found.")

# Function for web server enumeration and technology profiling
def web_server_enum_and_tech_profile(target, output_file):
    time.sleep(2)
    print(f"{Colors.BLUE}{Colors.BOLD}PERFORMING TECHNOLOGY PROFILING ON {target}{Colors.END}", flush=True)
    
    try:
        whatweb = subprocess.run(["whatweb", target], capture_output=True, text=True)
        with open(output_file, "a") as f:
            f.write("\n=== TECHNOLOGY PROFILING ===\n")
            f.write(whatweb.stdout + "\n")
        print(whatweb.stdout)
    except Exception as e:
        print(f"{Colors.RED}WhatWeb error: {e}{Colors.END}")

# Function to perform active reconnaissance
def active(target, output_file):
    print(f"{Colors.BLUE}{Colors.BOLD}CHECKING THE DOMAIN LIVE STATUS...{Colors.END}", flush=True)
    
    # Ping check
    try:
        ping = subprocess.run(["ping", "-c", "1", "-W", "1", target], capture_output=True, text=True)
        if ping.returncode == 0:
            print(f"{Colors.GREEN}{Colors.BOLD}THE DOMAIN IS LIVE. PROCEEDING WITH THE SCAN...{Colors.END}", flush=True)
        else:
            print(f"{Colors.RED}{Colors.BOLD}ERROR: THE DOMAIN IS NOT LIVE. EXITING SCAN...{Colors.END}", flush=True)
            sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Ping error: {e}{Colors.END}")
        sys.exit(1)
    
    print(f"{Colors.BLUE}{Colors.BOLD}PERFORMING ACTIVE RECONNAISSANCE...{Colors.END}", flush=True)
    time.sleep(2)
    
    with open(output_file, "a") as f:
        f.write("\n=== ACTIVE RECONNAISSANCE ===\n")
        
        # Subdomain enumeration
        f.write("\n--- Subdomain Enumeration ---\n")
        subdomain(target, output_file)
        
        # Directory enumeration
        surl = f"https://{target}"
        f.write("\n--- Directory Enumeration ---\n")
        directory_enum(surl, output_file)
        
        # Port scanning and service enumeration
        f.write("\n--- Port Scanning and Service Enumeration ---\n")
        try:
            nmap = subprocess.run(["nmap", "-A", target], capture_output=True, text=True)
            nmap_results = [line for line in nmap.stdout.splitlines() if "open" in line.lower() or "os" in line.lower()]
            f.write("\n".join(nmap_results) + "\n")
            print("\n".join(nmap_results))
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}Nmap error: {e}{Colors.END}")
        
        # WAF Detection
        f.write("\n--- WAF Detection ---\n")
        try:
            waf = subprocess.run(["python3", "waf.py", target], capture_output=True, text=True)
            f.write(waf.stdout + "\n")
            print(waf.stdout)
        except Exception as e:
            f.write(f"Error: {e}\n")
            print(f"{Colors.RED}WAF detection error: {e}{Colors.END}")
        
        # Admin Panel and robots.txt check
        f.write("\n--- Admin Panel Identification and robots.txt Enumeration ---\n")
        scrape(surl, output_file)
        
        # Web Server Enumeration and Technology Profiling
        web_server_enum_and_tech_profile(target, output_file)

# Function to create target folder and related directories
def create_target_folder(target, attack_type):
    target_folder = f"targets/{target}"
    targets_dir = "targets"
    
    try:
        # Create targets directory if it doesn't exist
        if not os.path.exists(targets_dir):
            os.makedirs(targets_dir)
        
        # Create target folder if it doesn't exist
        if not os.path.exists(target_folder):
            os.makedirs(target_folder)
        
        # Determine directory choice based on attack type
        if attack_type.lower() == "passive":
            directory_choice = "passive"
        elif attack_type.lower() == "active":
            directory_choice = "active"
        else:
            return False
        
        # Create 'active' or 'passive' directory if it doesn't exist
        directory_path = os.path.join(target_folder, directory_choice)
        if not os.path.exists(directory_path):
            os.makedirs(directory_path)
        
        # Create a text file with current date and time
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_file = os.path.join(directory_path, f"scanning_{current_time}.txt")
        open(output_file, 'a').close()  # Create empty file
        
        return output_file
    except Exception as e:
        print(f"{Colors.RED}Error creating target folder: {e}{Colors.END}")
        return False

# Function to configure Tor
def configure_tor():
    try:
        subprocess.run(["tor", "--version"], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        print(f"{Colors.RED}Tor could not be found. Please install Tor and try again.{Colors.END}")
        sys.exit(1)
    
    print(f"{Colors.RED}{Colors.BOLD}WARNING: ERRORS AND SLOW SCAN MAY BE EXPERIENCED WHEN USING TOR{Colors.END}")
    
    use_tor = input("Do you want to use Tor for anonymity? (y/n): ").strip().lower()
    
    if use_tor == 'y':
        print("Starting Tor service...")
        try:
            subprocess.run(["sudo", "service", "privoxy", "restart"], check=True)
            subprocess.run(["sudo", "service", "tor", "restart"], check=True)
            subprocess.run(["sudo", "service", "tor", "start"], check=True)
            subprocess.run(["sudo", "service", "privoxy", "start"], check=True)
            
            os.environ['http_proxy'] = 'http://127.0.0.1:8118'
            os.environ['https_proxy'] = 'http://127.0.0.1:8118'
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error starting Tor services: {e}{Colors.END}")

# Function to stop Tor services
def stop_tor():
    try:
        subprocess.run(["sudo", "service", "privoxy", "stop"], check=True)
        subprocess.run(["sudo", "service", "tor", "stop"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error stopping Tor services: {e}{Colors.END}")

# Function to select attack type
def select_attack_type(target):
    print("Select attack type:")
    print("* Passive\n* Active\n")
    attack = input().strip().lower()
    
    if attack in ["passive", "active"]:
        output_file = create_target_folder(target, attack)
        if output_file:
            if attack == "passive":
                print("\nStarting passive reconnaissance...")
                passive(target, output_file)
            else:
                print("\nStarting active reconnaissance...")
                active(target, output_file)
        else:
            print("\nFailed to create target folder. Exiting.")
            sys.exit(1)
    else:
        print("\nWrong choice...!!!!")
        select_attack_type(target)

# Main function
def main():
    webguard_banner()
    
    # Show loading effect
    stop_event = Event()
    loading_thread = Thread(target=loading_effect, args=(stop_event,))
    loading_thread.start()
    time.sleep(2)
    stop_event.set()
    loading_thread.join()
    
    print_dynamic_color("Recon Framework")
    print(f"{Colors.RED}{Colors.BOLD}ETHICAL CONSIDERATION NOTICE: ENSURE YOU HAVE EXPLICIT PERMISSION TO SCAN AND TEST THE TARGET. UNAUTHORIZED SCANNING IS ILLEGAL AND UNETHICAL.{Colors.END}")
    time.sleep(5)
    
    target = input("Enter target domain (example.com): ").strip()
    if not target:
        print(f"{Colors.RED}Error: No target specified.{Colors.END}")
        sys.exit(1)
    
    configure_tor()
    select_attack_type(target)
    stop_tor()

if __name__ == "__main__":
    main()
