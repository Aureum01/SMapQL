import logging
import json
import csv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Reporter:
    def __init__(self, vulnerable_domains):
        self.vulnerable_domains = vulnerable_domains

    def report(self, output_file="vulnerable_domains.txt"):
        output_format = output_file.split(".")[-1]

        if output_format == "json":
            self.report_json(output_file)
        elif output_format == "csv":
            self.report_csv(output_file)
        else:
            self.report_txt(output_file)

        logger.info("Vulnerabilities reported.")

    def report_json(self, output_file):
        with open(output_file, "w") as f:
            json.dump(list(self.vulnerable_domains), f, indent=4)

    def report_csv(self, output_file):
        with open(output_file, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["Domain"])
            for domain in self.vulnerable_domains:
                writer.writerow([domain])

    def report_txt(self, output_file):
        with open(output_file, "w") as f:
            for domain in self.vulnerable_domains:
                f.write(f"{domain}\n")
