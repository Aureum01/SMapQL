# SMapQL

## Description
SMapQL is a robust tool for detecting SQL Injection in sitemaps. It automates scanning of subdomains, identifies sitemaps, and tests for SQLi vulnerabilities. Designed for security researchers, it prioritizes accuracy and efficiency, reducing false positives and aiding vulnerability discovery.

## Features

- Concurrent testing using multiple threads
- Customizable delay between requests
- Proxy support
- Reporting of vulnerable domains in various formats (txt, json, csv)

## Requirements

- Python 3.10.10
Libraries:
argparse library
logging library
requests library
time library
json library
csv library
beautifulsoup4 (bs4) library
queue library
threading library
urllib library

## Installation


`pip install -r requirements.txt`

## Usage

`python script.py -t domain1.com domain2.com -th 10 -d 1 -o output.txt -p http://proxy.example.com:8080`

Command-line options:

    -t or --target_domains: Specify the target domains to check for SQL injection vulnerabilities. Multiple domains can be provided separated by spaces.
    -th or --threads: Specify the number of threads to use for concurrent requests. Default is 10 if not specified.
    -d or --delay: Specify the delay between requests in seconds. Default is 1 second if not specified.
    -o or --output: Specify the output file name for the vulnerabilities report. Default is "vulnerable_domains.txt" if not specified.
    -p or --proxies: Specify the proxies to use for requests. Format: http://proxy.example.com:8080

The script will perform the following steps:

    Fetch the sitemap files for the target domains.
    Parse the sitemap files and extract URLs.
    Test each URL for SQL injection vulnerabilities.
    Identify successful SQL injections and store the vulnerable domains.
    Generate a report in the specified output format (txt, json, or csv) containing the vulnerable domains.

Getting Help

To get help and see a list of available options, use the -h option:

bash

python3 smapql.py -h

Checking a Single Domain

To check a single domain with default settings (10 threads, 1 second delay, no proxies, output to vulnerable_domains.txt):

bash

python3 smapql.py -t example.com

Checking Multiple Domains

To check multiple domains with default settings:

bash

python3 smapql.py -t example1.com example2.com example3.com

Setting Threads and Delay Time

To check a single domain with 5 threads and a 2-second delay, outputting results to results.txt:

bash

python3 smapql.py -t example.com -th 5 -d 2 -o results.txt

Using a Proxy

To check a single domain with a proxy:

bash

    python3 smapql.py -t example.com -p http://yourproxy:8080

Please replace example.com and yourproxy:8080 with the actual domain and proxy you want to use.
## License:

MIT License

## Contributing:

Contributions are welcome! If you find any issues or want to enhance the tool, feel free to submit a pull request.

## Disclaimer:

This tool is meant for educational and professional testing purposes only. Use it responsibly and at your own risk.

## Author:

⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐
        Aureum01
⭐⭐⭐⭐⭐⭐⭐⭐⭐⭐

