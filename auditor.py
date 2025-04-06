from vulnerability_tester import VulnerabilityTester
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

class Auditor:
    def __init__(self, scanner, verbose=0):
        self.scanner = scanner
        self.verbose = verbose
        self.vulnerability_tester = VulnerabilityTester(self.scanner, verbose)
        self.logger = logging.getLogger(__name__)

    def log_verbose(self, message, level=1):
        if self.verbose >= level:
            print(f"[*] {message}")

    def audit_urls(self, crawled_urls):
        self.log_verbose("Starting vulnerability testing...", level=1)
        
        with ThreadPoolExecutor(max_workers=self.scanner.threads) as executor:
            futures = {executor.submit(self.vulnerability_tester.test_url, url): url for url in crawled_urls}
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error testing vulnerabilities: {str(e)}")
