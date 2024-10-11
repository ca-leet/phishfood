import argparse
import json
import logging
import random
import time
import csv
from typing import Dict, List
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup

class PhishFood:
    def __init__(self):
        self.api_keys = self.load_api_keys()
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            filename='phishfood.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        logging.getLogger().addHandler(logging.StreamHandler())

    def load_api_keys(self) -> Dict[str, str]:
        config_path = "config.json"
        try:
            with open(config_path, "r") as file:
                config = json.load(file)
                return config
        except FileNotFoundError:
            logging.error(f"Error: {config_path} file not found.")
            return {}
        except json.JSONDecodeError:
            logging.error(f"Error: {config_path} is not a valid JSON file.")
            return {}

    def get_user_input(self) -> Dict[str, str]:
        parser = argparse.ArgumentParser(description="PhishFood - OSINT Email Harvester and Domain Enumerator")
        parser.add_argument("-c", "--company", required=True, help="Target company name")
        parser.add_argument("-f", "--email_format", required=True, help="Email format (e.g., {f}.{last}@domain.com)")
        parser.add_argument("-d", "--domains", required=True, nargs='+', help="Target domains (e.g., example.com example2.com)")
        args = parser.parse_args()
        return vars(args)

    def harvest_emails(self, company: str, domain: str) -> List[Dict[str, str]]:
        emails = []
        emails.extend(self.linkedin_enum(company, domain))
        emails.extend(self.intelx_search(domain))
        emails.extend(self.dehashed_search(domain))
        emails.extend(self.maildb_search(domain))
        return emails

    def linkedin_enum(self, company: str, domain: str) -> List[Dict[str, str]]:
        search_engines = {
            'google': 'https://www.google.com/search?q=site:linkedin.com/in+"{}"&num=100&start={}',
            'bing': 'http://www.bing.com/search?q="{}"+site:linkedin.com/in&first={}'
        }
        results = []
        user_agent_list = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
        ]
        headers = {'User-Agent': random.choice(user_agent_list)}

        for engine, url_format in search_engines.items():
            page = 0
            while True:
                url = url_format.format(company, page)
                response = self.web_request(url, headers=headers)

                if not response or response.status_code != 200:
                    logging.warning(f"Non-200 response for {url}, stopping search for this engine.")
                    break

                emails = self.parse_search_results(response.content, domain, "LinkedIn")
                if not emails:
                    logging.info(f"No more results found for {engine}.")
                    break

                results.extend(emails)
                logging.info(f"Page {page} on {engine}: Found {len(emails)} email addresses.")
                page += 10
                time.sleep(random.uniform(2, 5))

        return results

    def web_request(self, url: str, headers: Dict[str, str], proxies: Dict[str, str] = {}) -> requests.Response:
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
            return response
        except requests.RequestException as e:
            logging.error(f"Request error: {e}")
            return None

    def parse_search_results(self, html_content: str, domain: str, source: str) -> List[Dict[str, str]]:
        soup = BeautifulSoup(html_content, 'html.parser')
        links = soup.find_all('a')
        email_addresses = []

        for link in links:
            href = link.get('href')
            if href and 'linkedin.com/in' in href:
                name = self.extract_name_from_link(href)
                if name:
                    email = self.generate_email_from_name(name, domain)
                    email_addresses.append({"email": email, "source": source})

        return email_addresses

    def extract_name_from_link(self, link: str) -> str:
        parsed_url = urlparse(link)
        path_segments = parsed_url.path.strip('/').split('/')
        
        if len(path_segments) > 1:
            profile_name = path_segments[1]
            profile_name = profile_name.replace('-', ' ').title()
            return profile_name
        return None

    def generate_email_from_name(self, name: str, domain: str) -> str:
        first, last = name.split()[0], name.split()[-1]
        email_format = self.get_user_input().get('email_format')
        return email_format.format(f=first[0], first=first, l=last[0], last=last, domain=domain)

    def save_emails(self, emails: List[Dict[str, str]], domain: str):
        filename = f"existant_users_{domain}.csv"
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Email', 'Source'])
            for entry in emails:
                writer.writerow([entry['email'], entry['source']])
        logging.info(f"Emails saved to {filename}")

    def validate_emails_concurrently(self, emails: List[Dict[str, str]], tenant_name: str) -> List[Dict[str, str]]:
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(self.validate_single_email, emails, [tenant_name] * len(emails)))
        return [email for email in results if email]

    def validate_single_email(self, email_entry: Dict[str, str], tenant_name: str) -> Dict[str, str]:
        email = email_entry['email']
        username = email.split('@')[0].replace(".", "_")
        domain = email.split('@')[1]

        url = f"https://{tenant_name}-my.sharepoint.com/personal/{username}_{domain}/_layouts/15/onedrive.aspx"
        logging.info(f"Validating email: {email}")
        try:
            r = requests.head(url, timeout=8.0, verify=False)
            status_code = r.status_code

            if status_code in [401, 403]:
                logging.info(f"Valid email: {email}")
                return email_entry
            elif status_code == 404:
                logging.info(f"Invalid email: {email}")
            else:
                logging.info(f"Odd response ({status_code}) for email: {email}")

        except requests.RequestException as e:
            logging.error(f"Error checking email {email}: {e}")

        return None

    def run(self):
        print("PhishFood - OSINT Email Harvester and Domain Enumerator")
        print("Disclaimer: This tool is for ethical and authorized use only.")
        confirmation = input("Do you have authorization to use this tool? (y/n): ")
        if confirmation.lower() != 'y':
            print("Authorization not confirmed. Exiting.")
            return

        user_input = self.get_user_input()
        company = user_input['company']
        email_format = user_input['email_format']
        domains = user_input['domains']

        for domain in domains:
            tenant_name = domain.split('.')[0]
            print(f"Harvesting emails for {company} ({domain})...")
            harvested_emails = self.harvest_emails(company, domain)
            print(f"Harvested {len(harvested_emails)} email addresses.")

            print("Validating email addresses...")
            valid_emails = self.validate_emails_concurrently(harvested_emails, tenant_name)
            print(f"Total valid email addresses: {len(valid_emails)}")

            self.save_emails(valid_emails, domain)

        print("Operation completed.")

if __name__ == "__main__":
    harvester = PhishFood()
    harvester.run()
