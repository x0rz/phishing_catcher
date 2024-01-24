#!/usr/bin/env python3
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import re
from collections import Counter
import math
import certstream
import tqdm
import yaml
import time
import os
from Levenshtein import distance
from termcolor import colored
from tld import get_tld
from confusables import unconfuse

domain_split_regex = re.compile("\W+")

certstream_url = 'wss://certstream.calidog.io'
log_suspicious = os.path.dirname(os.path.realpath(__file__)) + '/suspicious_domains_' + time.strftime("%Y-%m-%d") + '.log'
suspicious_yaml = os.path.dirname(os.path.realpath(__file__)) + '/suspicious.yaml'
external_yaml = os.path.dirname(os.path.realpath(__file__)) + '/external.yaml'
pbar = tqdm.tqdm(desc='certificate_update', unit='domains')

def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [float(count) / len(string) for count in Counter(string).values()]
    return -sum(p * math.log(p) / math.log(2.0) for p in prob)

def score_domain(domain, suspicious_tlds, suspicious_keywords):
    """Score `domain`."""
    score = 0

    if domain.startswith('*.'):
        domain = domain[2:]

    try:
        # Attempt to extract the TLD and process the domain
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])

        score += int(round(entropy(domain) * 10))
        domain = unconfuse(domain)
        words_in_domain = domain_split_regex.split(domain)

        if words_in_domain[0] in ['com', 'net', 'org']:
            score += 10

        for t in suspicious_tlds:
            if domain.endswith(t):
                score += 20

        for word in words_in_domain:
            if word in suspicious_keywords:
                score += suspicious_keywords[word]

        for key in [k for (k, s) in suspicious_keywords.items() if s >= 70]:
            for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
                if distance(str(word), str(key)) == 1:
                    score += 70

        if 'xn--' not in domain and domain.count('-') >= 4:
            score += domain.count('-') * 3

        if domain.count('.') >= 3:
            score += domain.count('.') * 3

    except UnicodeError as e:
        # Log the error and skip scoring for this domain
        print(f"Error processing domain '{domain}': {e}")
        return 0

    return score


def is_subdomain(domain, base_domain):
    return domain == base_domain or domain.endswith('.' + base_domain)

def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            domain_lower = domain.lower()

            if any(is_subdomain(domain_lower, ignore_domain) for ignore_domain in ignore_list):
                continue

            pbar.update(1)
            score = score_domain(domain_lower, suspicious_tlds_set, suspicious_keywords_set)

            if "Let's Encrypt" == message['data']['leaf_cert']['issuer']['O']:
                score += 10

            if "ZeroSSL" == message['data']['leaf_cert']['issuer']['O']:
                score += 10

            if score >= 100:
                tqdm.tqdm.write("[!] Suspicious: {} (score={})".format(colored(domain, 'red', attrs=['underline', 'bold']), score))
            elif score >= 90:
                tqdm.tqdm.write("[!] Suspicious: {} (score={})".format(colored(domain, 'red', attrs=['underline']), score))
            elif score >= 80:
                tqdm.tqdm.write("[!] Likely    : {} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
            elif score >= 65:
                tqdm.tqdm.write("[+] Potential : {} (score={})".format(colored(domain, attrs=['underline']), score))

            if score >= 75:
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))

if __name__ == '__main__':
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

    ignore_list = set(suspicious.get('ignore_domains', []))

    with open(external_yaml, 'r') as f:
        external = yaml.safe_load(f)

    if external.get('override_suspicious.yaml', False) is False:
        if external.get('keywords') is not None:
            suspicious['keywords'].update(external['keywords'])
        if external.get('tlds') is not None:
            suspicious['tlds'].update(external['tlds'])
        if external.get('ignore_domains') is not None:
            ignore_list.update(external['ignore_domains'])

    suspicious_tlds_set = set(suspicious.get('tlds', []))
    suspicious_keywords_set = {k: v for k, v in suspicious.get('keywords', {}).items()}

    certstream.listen_for_events(callback, url=certstream_url)