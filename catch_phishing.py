#!/usr/bin/env python
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
import os

import tqdm
import certstream

import entropy

log_suspicious = 'suspicious_domains({}).log'.format(
    len([item for item in os.listdir(os.getcwd()) if ".log" in item]) + 1
)

print("[!] log file being saved to {}\n".format(log_suspicious))

suspicious_keywords = [
    'login',
    'log-in',
    'account',
    'verification',
    'verify',
    'support',
    'activity',
    'security',
    'update',
    'authentication',
    'authenticate',
    'wallet',
    'alert',
    'purchase',
    'transaction',
    'recover',
    'live',
    'office'
]

highly_suspicious = [
    'paypal',
    'paypol',
    'poypal',
    'twitter',
    'appleid',
    'gmail',
    'outlook',
    'protonmail',
    'amazon',
    'facebook',
    'microsoft',
    'windows',
    'cgi-bin',
    'localbitcoin',
    'icloud',
    'iforgot',
    'isupport',
    'kraken',
    'bitstamp',
    'bittrex',
    'blockchain',
    '.com-',
    '-com.',
    '.net-',
    '.org-',
    '.gov-',
    '.gouv-',
    '-gouv-'
]

suspicious_tld = [
    '.ga',
    '.gq',
    '.ml',
    '.cf',
    '.tk',
    '.xyz',
    '.pw',
    '.cc',
    '.club',
    '.work',
    '.top',
    '.support',
    '.bank',
    '.info',
    '.study',
    '.party',
    '.click',
    '.country',
    '.stream',
    '.gdn',
    '.mom',
    '.xin',
    '.kim',
    '.men',
    '.loan',
    '.download',
    '.racing',
    '.online',
    '.ren',
    '.gb',
    '.win',
    '.review',
    '.vip',
    '.party',
    '.tech',
    '.science'
]

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')


def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    if any(domain.endswith(tld) for tld in suspicious_tld):
        score += 20
    if any(keyword in domain for keyword in suspicious_keywords):
        score += 25
    if any(name in domain for name in highly_suspicious):
        score += 60

    # due to `any()` (idk why) this needs to be doubled
    score += int(round(entropy.shannon_entropy(domain)*100))

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += 20

    # make up for the lack of the single point deduction to the way `any()` is working
    score += 1
    return score


def callback(message, *args):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        with open(log_suspicious, 'a') as f:
            for domain in all_domains:
                pbar.update(1)
                score = score_domain(domain)
                if score > 75:
                    tqdm.tqdm.write(
                        "\033[91mSuspicious: "
                        "\033[4m{}\033[0m\033[91m (score={})\033[0m".format(domain, score))
                    f.write("{}\n".format(domain))
                elif score > 65:
                    tqdm.tqdm.write(
                        "Potential: "
                        "\033[4m{}\033[0m\033[0m (score={})".format(domain, score))


certstream.listen_for_events(callback)