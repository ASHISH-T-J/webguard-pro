import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class Crawler:
    def __init__(self, domain, threads=10, verbose=0):
        self.domain = domain
        self.threads = threads
        self.verbose = verbose
        self.crawled_urls = set()
        self.visited_urls = set()
        self.logger = logging.getLogger(__name__)

    def log_verbose(self, message, level=1):
        if self.verbose >= level:
            print(f"[*] {message}")

    def crawl_urls(self, live_hosts, depth=2):
        url_queue = [(host['url'], depth) for host in live_hosts]
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
        return list(self.crawled_urls)

    def _crawl_single_url(self, url, depth):
        if depth == 0 or url in self.visited_urls:
            return []

        self.visited_urls.add(url)  # Mark URL as visited
        self.logger.info(f"Crawling: {url}")
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)

            if 'text/html' not in response.headers.get('Content-Type', ''):
                return []

            soup = BeautifulSoup(response.text, 'html.parser')
            
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
