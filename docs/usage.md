# Smapql Usage Guide

Smapql is a powerful tool designed to help you discover and test SQL injection vulnerabilities in sitemaps. This guide provides detailed instructions on how to use Smapql effectively and maximize its capabilities.
Installation

To install Smapql, follow these steps:

## Prerequisites

    Python 3.10.11 or later installed on your system.

## Clone the Repository

    Clone the Smapql repository from GitHub:


`git clone https://github.com/Aureum01/smapql.git`

## Navigate to the project directory:

    `cd smapql`

## Install Dependencies

    Install the required dependencies using pip:


    `pip install -r requirements.txt`

## Usage

To use Smapql, follow the steps below:

### Step 1: Specify Target Domains

Open a terminal and navigate to the Smapql project directory.

### Step 2: Run the Smapql Tool

Run the Smapql tool with the following command:



`python src/main.py -t <target_domains> [options]`

Replace <target_domains> with a space-separated list of the target domains you want to check. For example:



`python src/main.py -t example.com example.org example.net`

### Step 3: Customize the Tool's Behavior (Optional)

You can specify additional options to customize the tool's behavior:

    -th, --threads <num>: Number of threads to use (default: 10).
    -d, --delay <seconds>: Delay between requests in seconds (default: 1).
    -o, --output <file>: Output file name for reporting vulnerabilities (default: vulnerable_domains.txt).
    -p, --proxies <proxies>: Proxies to use for requests (optional).

Example:


`python src/main.py -t example.com example.org -th 5 -d 2 -o report.txt`

### Step 4: Discover and Test Sitemaps

Smapql will automatically discover sitemaps for the target domains and test them for SQL injection vulnerabilities.

### Step 5: Review the Vulnerability Report

After running Smapql, a vulnerability report will be generated. The report provides detailed information about the discovered SQL injection vulnerabilities.

To view the report, open the specified output file (default: vulnerable_domains.txt) using a text editor or other suitable tools.
Reporting

Smapql provides various output formats for the vulnerability report. By default, the report is saved in plain text format. However, you can choose from the following output formats:

    JSON: The vulnerabilities will be reported in a JSON file.
    CSV: The vulnerabilities will be reported in a CSV file.
    TXT (default): The vulnerabilities will be reported in a plain text file.

## Example

Here's an example command to run Smapql on multiple target domains:


`python src/main.py -t example.com example.org -th 5 -d 2 -o report.json`

This command will test the sitemaps of example.com and example.org for SQL injection vulnerabilities using 5 threads, a delay of 2 seconds between requests, and generate a JSON vulnerability report named report.json.

Feel free to modify the command based on your specific requirements and domain targets.
Notes

    Ensure that you have proper authorization and permission to test the target domains for vulnerabilities.
    Use this tool responsibly and respect the security and privacy of others.
