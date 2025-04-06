import json
import requests
import subprocess
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
from datetime import datetime
from vulnerability_tester import VulnerabilityTester
from colorama import init, Fore, Style
from ratelimit import limits, sleep_and_retry
import html  # Import the html module for escaping HTML content

# Initialize colorama
init(autoreset=True)

class WebScanner:
    def __init__(self, domain, threads=10, include_subdomains=False, verbose=0):
        self.domain = domain
        self.threads = threads
        self.include_subdomains = include_subdomains
        self.verbose = verbose
        self.subdomains = set()
        self.live_hosts = []
        self.crawled_urls = set()
        self.vulnerabilities = []
        self.setup_logging()
        self.session = requests.Session()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.vulnerability_tester = VulnerabilityTester(self, verbose)
        self.request_rate_limit = 10  # Requests per second
        self.last_request_time = 0
        self.visited_urls = set()  # Track visited URLs to avoid reprocessing

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'{self.domain}_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def log_verbose(self, message, level=1):
        if self.verbose >= level:
            print(Fore.YELLOW + f"[*] {message}")

    def log_warning(self, message):
        print(Fore.RED + f"[!] {message}")

    def log_success(self, message):
        print(Fore.GREEN + f"[+] {message}")

    def log_info(self, message):
        print(Fore.CYAN + f"[*] {message}")

    def log_debug(self, message):
        if self.verbose >= 2:  # Only show debug logs in -vv mode
            print(Fore.BLUE + f"[DEBUG] {message}")

    def get_random_user_agent(self):
        return random.choice(self.user_agents)

    @sleep_and_retry
    @limits(calls=10, period=1)  # Rate limit: 10 requests per second
    def rate_limited_request(self, method, url, **kwargs):
        return method(url, **kwargs)

    def enumerate_subdomains(self):
        if not self.include_subdomains:
            self.log_verbose("Subdomain enumeration skipped", level=1)
            return list(self.subdomains)

        self.log_info(f"Starting subdomain enumeration for {self.domain}")
        
        try:
            self.log_verbose("Running subfinder...", level=2)
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent"],
                capture_output=True,
                text=True
            )
            if result.stdout:
                self.subdomains.update(result.stdout.splitlines())
                self.log_verbose(f"Subfinder found {len(self.subdomains)} subdomains", level=2)
        except Exception as e:
            self.log_warning(f"Subfinder error: {str(e)}")

        return list(self.subdomains)

    def check_live_hosts(self):
        self.log_info("Checking for live hosts...")
        
        def check_host(subdomain):
            results = []
            for protocol in ['http', 'https']:
                url = f"{protocol}://{subdomain.strip()}"
                try:
                    headers = {'User-Agent': self.get_random_user_agent()}
                    response = self.rate_limited_request(requests.head, url, headers=headers, timeout=5, allow_redirects=True)
                    if response.status_code < 400:
                        info = {
                            'url': url,
                            'status_code': response.status_code,
                            'server': response.headers.get('Server', 'Unknown'),
                            'technologies': []
                        }
                        for header, value in response.headers.items():
                            if any(tech in value.lower() for tech in ['php', 'apache', 'nginx', 'iis']):
                                info['technologies'].append(f"{header}: {value}")
                        results.append(info)
                except Exception:
                    continue
            return results

        # If subdomains are included, check both the main domain and subdomains
        check_list = [self.domain] + list(self.subdomains) if self.include_subdomains else [self.domain]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_host, host): host for host in check_list}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.live_hosts.extend(result)

        self.log_info(f"Found {len(self.live_hosts)} live hosts")
        return self.live_hosts

    def crawl_and_audit(self, depth=2):
        self.log_info("Starting crawling and auditing...")
        
        # Perform crawling first
        self.crawl_urls(depth=depth)
        
        # Deduplicate and sort URLs
        self.crawled_urls = list(set(self.crawled_urls))
        self.crawled_urls.sort()

        # Perform vulnerability testing on crawled URLs
        self.test_vulnerabilities()

    def crawl_urls(self, depth=2):
        url_queue = [(host['url'], depth) for host in self.live_hosts]
        processed_urls = set()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while url_queue:
                current_urls = url_queue[:self.threads]
                url_queue = url_queue[self.threads:]

                futures = {}
                for current_url, current_depth in current_urls:
                    if current_url in processed_urls or current_depth == 0:
                        continue
                    
                    futures[executor.submit(self._crawl_single_url, current_url, current_depth)] = current_url

                for future in as_completed(futures):
                    try:
                        new_urls = future.result()
                        for new_url, new_depth in new_urls:
                            if new_url not in processed_urls and self.domain in new_url:
                                url_queue.append((new_url, new_depth - 1))
                        
                        processed_urls.add(futures[future])
                    except Exception as e:
                        self.logger.error(f"Crawling error: {str(e)}")

                if len(processed_urls) > 100:
                    break

        self.crawled_urls = processed_urls

    def _crawl_single_url(self, url, depth):
        if depth == 0 or url in self.visited_urls:
            return []

        self.visited_urls.add(url)  # Mark URL as visited
        self.logger.info(f"Crawling: {url}")
        try:
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.rate_limited_request(requests.get, url, headers=headers, timeout=10)

            if 'text/html' not in response.headers.get('Content-Type', ''):
                return []

            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                self.vulnerability_tester.analyze_form(url, form)

            new_urls = []
            links = soup.find_all('a')
            for link in links:
                href = link.get('href')
                if href:
                    full_url = urljoin(url, href)
                    if self.domain in full_url and full_url not in self.visited_urls:
                        new_urls.append((full_url, depth))

            return new_urls

        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")
            return []

    def test_vulnerabilities(self):
        self.log_info("Starting vulnerability testing...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.vulnerability_tester.test_url, url): url for url in self.crawled_urls}
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error testing vulnerabilities: {str(e)}")

    def generate_report(self):
        json_filename = f"{self.domain}_{self.timestamp}_scan_report.json"
        html_filename = f"{self.domain}_{self.timestamp}_scan_report.html"

        report = {
            'scan_info': {
                'target_domain': self.domain,
                'scan_date': datetime.now().isoformat(),
                'total_subdomains': len(self.subdomains),
                'total_live_hosts': len(self.live_hosts),
                'total_urls_crawled': len(self.crawled_urls),
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'subdomains': list(self.subdomains),
            'live_hosts': self.live_hosts,
            'crawled_urls': list(self.crawled_urls),
            'vulnerabilities': self.vulnerabilities
        }

        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=4)

        self.generate_html_report(report, html_filename)
        
        self.log_success(f"Scan completed. Reports generated: {json_filename} and {html_filename}")
        return report

    def generate_html_report(self, report, filename):
        # Escape special characters in the report data
        def escape_html(data):
            if isinstance(data, str):
                return html.escape(data)
            elif isinstance(data, dict):
                return {k: escape_html(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [escape_html(item) for item in data]
            return data

        # Escape all data in the report
        report = escape_html(report)

        html_content = f"""
        <html>
            <head>
                <title>Scan Report - {report['scan_info']['target_domain']}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                    .vulnerability {{ background-color: #fff3f3; padding: 10px; margin: 10px 0; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ padding: 8px; text-align: left; border: 1px solid #ddd; }}
                    th {{ background-color: #f5f5f5; }}
                    .high {{ color: #d9534f; }}
                    .medium {{ color: #f0ad4e; }}
                    .low {{ color: #5bc0de; }}
                </style>
            </head>
            <body>
                <h1>Web Vulnerability Scan Report</h1>
                <div class="section">
                    <h2>Scan Summary</h2>
                    <p>Target Domain: {report['scan_info']['target_domain']}</p>
                    <p>Scan Date: {report['scan_info']['scan_date']}</p>
                    <p>Total Subdomains: {report['scan_info']['total_subdomains']}</p>
                    <p>Live Hosts: {report['scan_info']['total_live_hosts']}</p>
                    <p>URLs Crawled: {report['scan_info']['total_urls_crawled']}</p>
                    <p>Vulnerabilities Found: {report['scan_info']['total_vulnerabilities']}</p>
                </div>
                
                <div class="section">
                    <h2>Vulnerabilities</h2>
                    {self._generate_vulnerability_table(report['vulnerabilities'])}
                </div>
                
                <div class="section">
                    <h2>Live Hosts</h2>
                    {self._generate_host_table(report['live_hosts'])}
                </div>
            </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)

    def _generate_vulnerability_table(self, vulnerabilities):
        if not vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
            
        table = """
        <table>
            <tr>
                <th>Type</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Payload</th>
                <th>Confidence</th>
                <th>Timestamp</th>
            </tr>
        """
        
        for vuln in vulnerabilities:
            confidence_class = vuln.get('confidence', 'Medium').lower()
            table += f"""
            <tr>
                <td>{vuln.get('type', 'N/A')}</td>
                <td>{vuln.get('url', 'N/A')}</td>
                <td>{vuln.get('parameter', 'N/A')}</td>
                <td>{vuln.get('payload', 'N/A')}</td>
                <td class="{confidence_class}">{vuln.get('confidence', 'Medium')}</td>
                <td>{vuln.get('timestamp', 'N/A')}</td>
            </tr>
            """
        
        table += "</table>"
        return table

    def _generate_host_table(self, hosts):
        if not hosts:
            return "<p>No live hosts found.</p>"
            
        table = """
        <table>
            <tr>
                <th>URL</th>
                <th>Status Code</th>
                <th>Server</th>
                <th>Technologies</th>
            </tr>
        """
        
        for host in hosts:
            table += f"""
            <tr>
                <td>{host['url']}</td>
                <td>{host['status_code']}</td>
                <td>{host['server']}</td>
                <td>{', '.join(host['technologies'])}</td>
            </tr>
            """
        
        table += "</table>"
        return table
