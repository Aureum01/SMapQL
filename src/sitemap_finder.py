import requests
import logging
from threading import Thread
from queue import Queue
import time
from urllib.parse import urljoin, urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SitemapFinder:
    def __init__(self, target_domains, thread_count, rate_limit_delay=1, proxies=None):
        self.target_domains = target_domains
        self.thread_count = thread_count
        self.rate_limit_delay = rate_limit_delay
        self.proxies = proxies
        self.sitemap_subdomains = []
        self.queue = Queue()

    def find_sitemaps(self):
        # Worker function for threads.
        def worker():
            while not self.queue.empty():
                domain = self.queue.get()
                try:
                    response = requests.get(
                        f"https://{domain}/sitemap.xml", proxies=self.proxies
                    )
                    if response.status_code == 200:
                        self.sitemap_subdomains.append(domain)
                except requests.exceptions.RequestException as e:
                    logger.error(f"An error occurred: {e}")
                finally:
                    self.queue.task_done()
                    time.sleep(self.rate_limit_delay)

        # Adding all domains to queue.
        for domain in self.target_domains:
            self.queue.put(domain)

        # Starting worker threads.
        for _ in range(self.thread_count):
            thread = Thread(target=worker)
            thread.start()

        # Waiting for all threads to finish.
        self.queue.join()
        logger.info(f"Found {len(self.sitemap_subdomains)} domains with sitemaps.")
        return self.sitemap_subdomains
