# SMapQL

## Description
SMapQL is a robust tool for detecting SQL Injection in sitemaps. It automates scanning of subdomains, identifies sitemaps, and tests for SQLi vulnerabilities. Designed for security researchers, it prioritizes accuracy and efficiency, reducing false positives and aiding vulnerability discovery.

## Features

- Concurrent testing using multiple threads
- Customizable delay between requests
- Proxy support
- Reporting of vulnerable domains in various formats (txt, json, csv)

## Requirements

- Python 3.x
- `argparse` library
- `requests` library
- `beautifulsoup4` library

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

