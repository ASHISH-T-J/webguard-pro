import argparse
import time
from web_scanner import WebScanner
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="Web Application Vulnerability Scanner")
    parser.add_argument("-d", "--domains", nargs="+", help="Target domains to scan (space-separated)")
    parser.add_argument("-f", "--file", help="File containing list of domains (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("--subdomains", action="store_true", help="Include subdomains in the scan")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose mode (use -v for basic, -vv for full)")
    args = parser.parse_args()

    # Validate domain inputs
    domains = []
    if args.domains:
        domains.extend(args.domains)
    if args.file:
        try:
            with open(args.file, "r") as f:
                domains.extend(line.strip() for line in f if line.strip())
        except Exception as e:
            print(Fore.RED + f"[!] Error reading file: {str(e)}")
            return

    if not domains:
        print(Fore.RED + "[!] No domains provided. Use -d or -f to specify domains.")
        return

    try:
        for domain in domains:
            print(Fore.GREEN + f"\n[+] Starting scan for domain: {domain}")
            
            # Initialize the scanner
            scanner = WebScanner(
                domain, 
                threads=args.threads, 
                include_subdomains=args.subdomains,
                verbose=args.verbose
            )
            
            if args.subdomains:
                print(Fore.CYAN + "[+] Enumerating subdomains...")
                subdomains = scanner.enumerate_subdomains()
                if args.verbose:
                    print(Fore.CYAN + f"[*] Found subdomains: {', '.join(subdomains)}")
            
            print(Fore.CYAN + "[+] Checking for live hosts...")
            live_hosts = scanner.check_live_hosts()
            if args.verbose:
                print(Fore.CYAN + f"[*] Found live hosts: {', '.join([host['url'] for host in live_hosts])}")
            
            print(Fore.CYAN + "[+] Crawling and auditing websites...")
            start_time = time.time()
            scanner.crawl_and_audit(depth=args.depth)
            crawl_time = time.time() - start_time
            print(Fore.CYAN + f"[+] Crawling completed in {crawl_time:.2f} seconds.")
            
            print(Fore.CYAN + "[+] Starting vulnerability testing...")
            start_time = time.time()
            scanner.test_vulnerabilities()
            test_time = time.time() - start_time
            print(Fore.CYAN + f"[+] Vulnerability testing completed in {test_time:.2f} seconds.")
            
            print(Fore.CYAN + "[+] Generating report...")
            scanner.generate_report()
        
        print(Fore.GREEN + "\n[+] Scan completed successfully!")
        print(Fore.GREEN + "[+] Check *_scan_report.json and *_scan_report.html for detailed results")
        
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
    except Exception as e:
        print(Fore.RED + f"\n[!] An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
