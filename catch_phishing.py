#!/usr/bin/env python
"""
Copyright (c) 2017 @x0rz

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""


import re
import math
import certstream
from tqdm import tqdm
import yaml
from pathlib import Path
import time
from datetime import datetime
import socket
import string
from Levenshtein import distance
from termcolor import colored
from tld import get_tld
import concurrent.futures
from confusables import unconfuse
from log_rotate import *


# Defining global variables
CERTSTREAM_URL = 'wss://certstream.calidog.io'
ISSUERS = Path(__file__).resolve().parent / 'issuers_list.txt'
SUSPICIOUS_YAML = Path(__file__).resolve().parent / 'suspicious.yaml'
EXTERNAL_YAML = Path(__file__).resolve().parent / 'external.yaml'
CHAR = string.ascii_lowercase
PBAR = tqdm(desc='certificate_update', unit='cert')
# List of paterns to ignore
IGNORED_PATTERNS = ["*."]

# Working directories (.log)
WORKING_LOG_DIRECTORY = Path(__file__).resolve().parent.parent
NO_LETSENCRYPT_FILE = Path(__file__).resolve().parent.parent / f'no-letsencrypt.txt'
POTENTIAL_DOMAINS = Path(__file__).resolve().parent.parent / f'potential_domains.log'
SUSPICIOUS_DOMAINS = Path(__file__).resolve().parent.parent / f'suspicious_domains.log'
PROBLEMATIC_DOMAINS = Path(__file__).resolve().parent.parent / f'problematic_domains.log'
WORKING_LOG_FILES = [NO_LETSENCRYPT_FILE, SUSPICIOUS_DOMAINS, POTENTIAL_DOMAINS, PROBLEMATIC_DOMAINS]

# Data loaded once during initialisation ("issuers" and YAML and variables for callback())
issuers = None
suspicious = None
CREATION_DATE = ""
EXPIRATION_DATE = ""
SCORE = 0
ISSUER = ""
DOMAIN_NAME_TO_IP = None


def load_issuers(file_path):
    with open(file_path, 'r') as file:
        return {line.strip() for line in file}


def initialize():
    """Initialise the various files used"""
    global issuers, suspicious

    try:
        issuers = load_issuers(ISSUERS)
        
        for working_log_file in WORKING_LOG_FILES:
            if not os.path.exists(working_log_file):
                with open(os.path.join(WORKING_LOG_DIRECTORY, working_log_file), 'w') as f:
                    continue
        
        with open(SUSPICIOUS_YAML, 'r') as f:
            suspicious = yaml.safe_load(f)

        with open(EXTERNAL_YAML, 'r') as f:
            external = yaml.safe_load(f)

        if external.get('override_suspicious.yaml', False):
            suspicious = external
        else:
            if external.get('keywords'):
                suspicious['keywords'].update(external['keywords'])

            if external.get('tlds'):
                suspicious['tlds'].update(external['tlds'])

    except Exception as e:
        print(f"Error loading configuration files: {e}")
        exit(1)


def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy


def should_ignore_domain(domain):
    """Check if the domain should be ignored based on the patterns."""
    return any(domain.startswith(pattern) for pattern in IGNORED_PATTERNS)


def score_domain(domain):
    score = 0
    
    # Check for suspect TLDs
    tld = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
    if tld and tld.tld in suspicious['tlds']:
        score += suspicious['tlds'].get(tld.tld, 20)  # Score par défaut de 20 si non spécifié

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com) / Extract the main domain
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        main_domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        main_domain = domain

    # Higer entropy is kind of suspicious (Calculate the entropy of the domain, The higher it is, the more suspicious it is)
    domain_entropy = entropy(main_domain)
    if domain_entropy >= 3.1:  # Adjustable threshold
        score += int(round(domain_entropy * 10))
        # print(f"\n[DEBUG] Domain entropy: {domain_entropy}\n")

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    clean_domain = unconfuse(main_domain)
    words_in_domain = re.split(r'\.|-|_', clean_domain.lower())

    # ie. detect fake .com (ie. *.com-account-management.info)
    fake_tld_score = 40
    for word in words_in_domain:
        if word in ['com', 'net', 'org', 'gov', 'gouv']:
            score += fake_tld_score

    # Test for suspicious keywords
    keyword_count = 0
    for word, keyword_score in suspicious['keywords'].items():
        if word in clean_domain:
            score += keyword_score
            keyword_count += 1
    
    # Penalising domains containing too many suspect keywords
    if keyword_count > 2:
        score += (keyword_count - 2) * 10

    # Test Levenshtein distance for strong keywords (>= 70 points)
    strong_keyword_threshold = 55
    levenshtein_score = 70
    for key, keyword_score in suspicious['keywords'].items():
        if keyword_score >= strong_keyword_threshold:
            for word in words_in_domain:
                if len(word) > 3 and word not in ['email', 'mail', 'cloud', 'online', 'service', 'support']:
                    if distance(word, key) == 1:
                        score += levenshtein_score

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain:
        hyphen_count = domain.count('-')
        if hyphen_count >= 4:
            score += hyphen_count * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    dot_count = domain.count('.')
    if dot_count >= 3:
        score += dot_count * 3

    return score


def check_domain(domain):
    global DOMAIN_NAME_TO_IP
    try:
        DOMAIN_NAME_TO_IP = socket.gethostbyname(domain)
    except Exception:
        DOMAIN_NAME_TO_IP = 'IP not resolved'


def contains_keyword_or_tld(domain, keywords, tlds):
    """Check if the domain contains any exact keywords or TLDs."""
    # Dividing the domain into segments
    words_in_domain = re.split(r'\.|-|_', domain.lower())
    
    # Check whether an exact keyword is present in the domain
    for keyword, score in keywords.items():
        if keyword.lower() in words_in_domain:
            return True, keyword, score
    
    # Check whether the domain's TLD appears in the list of TLDs
    tld = '.' + domain.split('.')[-1].lower()  # Extract the domain's TLD
    if tld in tlds:
        return True, tld, 0  # The TLD score can be managed separately if required.
    
    return False, None, None


def write_to_file(file_path, domain, creation_date, expiration_date, ip, issuer, score, keyword_or_tld=None):
    """Centralise writing to files"""
    # Check whether the domain contains a keyword or tld from the suspicious.yaml file
    keywords, tlds = suspicious.get('keywords', {}), suspicious.get('tlds', {})
    contains_kw, keyword_or_tld, keyword_score = contains_keyword_or_tld(domain, keywords, tlds)
    
    with open(file_path, 'a') as f:
        line = f"{domain}, {creation_date}, {expiration_date}, {ip}, {issuer.split(',')[0]}, {score}"
        if keyword_or_tld:
            line += f", {keyword_or_tld}"
            f.write(line + "\n")
        else:
            f.write(line + "\n")


def get_category_info(score):
    """defines the domain category."""
    if score < 70:
        return "+  Potential", None, []
    elif score >= 70 and score < 80:
        return "!  Likely", "yellow", []
    elif score >= 80 and score < 90:
        return "!  Suspicious", "red", []
    else:
        return "!  Problematic", "red", ["bold"]


def log_result(domain, ip, issuer, score, creation_date, expiration_date):
    """defines and builds the "tqdm" display."""
    category, color, attrs = get_category_info(score)
    
    message = (
        f"[{category[0]}] {category[1:].ljust(11)}: {colored(domain, color, attrs=['underline'] + attrs)}\n"
        f"\t\t\t- IP: {ip}\n"
        f"\t\t\t- Score: {colored(score, attrs=['bold']) if score >= 80 else score}\n"
        f"\t\t\t- Issuer: {issuer.split(',')[0]}\n"
        f"\t\t\t- Creation: {creation_date}\n"
        f"\t\t\t- Expiration: {expiration_date}"
    )
    
    tqdm.write(message)


def process_domain(domain, message, creation_date, expiration_date, score, DOMAIN_NAME_TO_IP, issuer):
    """Process each domain to update the score and check the issuer."""
    PBAR.update(1)
    # Check whether the domain should be ignored
    if should_ignore_domain(domain):
        return

    # Check whether the certificate issuer is on the list
    issuer = message['data']['leaf_cert']['issuer'].get('O')
    if issuer not in issuers:  # Used to find issuers
        with open(NO_LETSENCRYPT_FILE, 'a') as f:
            f.write(f"'not Lets Encrypt', {issuer}\n")
        return

    # Calculate the domain score
    score = score_domain(domain.lower())

    # Resolve the domain to obtain the IP
    check_domain(domain)

    # Extract certificate informations (creation and expiry dates, certificatePolicies, Organization & Common Name)
    creation_date = None
    expiration_date = None

    try:
        leaf_cert = message['data']['leaf_cert']
        if 'not_before' in leaf_cert and 'not_after' in leaf_cert:
            creation_date = datetime.fromtimestamp(leaf_cert['not_before'])
            expiration_date = datetime.fromtimestamp(leaf_cert['not_after'])
    except Exception:
        creation_date = None
        expiration_date = None

    # Add points for a issuer in the list
    if issuer in issuers:
        score += 10

        # Logging and recording results
        log_result(domain, DOMAIN_NAME_TO_IP, issuer, score, creation_date, expiration_date)

        # Determine the appropriate file path based on the score
        if score < 70:
            target_file = POTENTIAL_DOMAINS
        elif score >= 70 and score < 90:
            target_file = SUSPICIOUS_DOMAINS
        else:
            target_file = PROBLEMATIC_DOMAINS

        # Write the basic domain information
        write_to_file(target_file, domain, creation_date, expiration_date, DOMAIN_NAME_TO_IP, issuer, score)
                    
        # Implementing and using the log rotation class
        time.sleep(1)
        log_manager = LogManager(LOG_FILES, FINAL_REPO_PATH, FINAL_FILE_PATHS, ARCHIVE_DIR, MAX_FILE_SIZE)
        log_manager.log_rotate()


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_domain, domain, message, CREATION_DATE, EXPIRATION_DATE, 
                                       SCORE, DOMAIN_NAME_TO_IP, ISSUER) for domain in all_domains]
            for future in concurrent.futures.as_completed(futures):
                future.result()  # Ensures that all tasks are completed


if __name__ == '__main__':
    initialize()
    certstream.listen_for_events(callback, url=CERTSTREAM_URL)
