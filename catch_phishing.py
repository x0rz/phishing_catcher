#!/usr/bin/python3
# -*- coding: utf-8 -*-
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

import logging
import sys
import datetime
import certstream
import entropy
import inspect
import tqdm

log_suspicious = 'suspicious_domains.log'

suspicious_keywords = [
    'login',
    'log-in',
    'account',
    'verification',
    'verify',
    'support',
    'security',
    'authentication',
    'authenticate',
    'wallet',
    'alert',
    'purchase',
    'recover'
    ]

highly_suspicious = [
    'paypal',
    'paypol',
    'poypal',
    'twitter',
    'appleid',
    'gmail',
    'amazon',
    'facebook',
    'cgi-bin',
    'localbitcoin',
    'icloud',
    'kraken',
    'bitstamp',
    'blockchain',
    '.com-',
    '-com.',
    '.net-',
    '.org-',
    '.gov-'
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
    '.stream',
    '.science'
    ]

# store builtin print
old_print = print
def new_print(*args, **kwargs):
    # if tqdm.tqdm.write raises error, use builtin print
    try:
        tqdm.tqdm.write(*args, **kwargs)
    except:
        old_print(*args, ** kwargs)
# globaly replace print with new_print
inspect.builtins.print = new_print

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')

# scoring function (hackish, could be better but it works so far)
def score_domain(domain):
    score = 0
    for tld in suspicious_tld:
        if domain.endswith(tld):
            score += 20
    for keyword in suspicious_keywords:
        if keyword in domain:
            score += 25
    for keyword in highly_suspicious:
        if keyword in domain:
            score += 60
    score += int(round(entropy.shannon_entropy(domain)*50))

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if not 'xn--' in domain and domain.count('-') >= 4:
        score += 20
    return score

def callback(message, context):
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain)
            if score > 75:
                print("\033[91mSuspicious: \033[4m%s\033[0m\033[91m (score=%s)\033[0m" % (domain, score))
                with open(log_suspicious, 'a') as f:
                    f.write("%s\n" % domain)
            elif score > 65:
                print("Potential: \033[4m%s\033[0m\033[0m (score=%s)" % (domain, score))

certstream.listen_for_events(callback)
