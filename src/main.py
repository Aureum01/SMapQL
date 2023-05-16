import argparse
import logging
from src.sitemap_finder import SitemapFinder
from src.sqli_tester import SqliTester
from src.reporter import Reporter

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


if __name__ == "__main__":
    args = parse_arguments()
    proxies = {"http": args.proxies, "https": args.proxies} if args.proxies else None

    sitemap_finder = SitemapFinder(args.target_domains, args.threads, args.delay, proxies)
    sitemap_subdomains = sitemap_finder.find_sitemaps()

    sqli_tester = SqliTester(sitemap_subdomains, args.threads, args.delay, proxies)
    sqli_tester.test_sqli()
    vulnerable_domains = sqli_tester.vulnerable_domains

    reporter = Reporter(vulnerable_domains)
    reporter.report(args.output)
