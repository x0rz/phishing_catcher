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
import certstream
import tqdm

import entropy

log_suspicious = 'suspicious_domains.log'

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
# money
    'paypal',
    'kraken',
    'bitstamp',
    'bittrex',
    'poloniex',
    'blockchain',
    'bithumb',
    'localbitcoin',
    'bitflyer',
    'gdax',
    'coinbase',
    'hitbtc',
    'lakebtc',
    'gemini',
    'btcc',
    'coinone',
    'bitfinex',
    'itbit',
    'korbit',
    'bitconnect',
    'coinest',
    'huobi',
    'binance',
    'coinsbank',
    'bitbay',
    'yobit',
    'payza',
    'moneygram',
    'westernunion',
    'bankofamerica',
    'wellsfargo',
    'citigroup',
    'bancorp',
    'santander',
    'chase',
    'pnc',
    'morganstanley',
    'scottrade',
    'etrade',
    'ameritrade'
    'fidelity',
    'merilledge',
# email
    'protonmail',
    'tutanota',
    'hotmail',
    'gmail',
    'outlook',
    'yahoo',
    'aol',
    'google',
    'yandex',
    'gmx',
    'appleid', 'icloud', 'iforgot', 'isupport',
# social media
    'twitter',
    'facebook',
    'tumblr',
    'reddit',
    'youtube',
    'linkedin',
    'instagram',
    'flickr',
    'whatsapp',

# deceptive
    '.com-', '-com.',
    '.net-', '-net.',
    '.org-', '-org.',
    '.gov-', '-gov.',
    '.gouv-',
    '-gouv-',
# ecommerce
    'amazon',
    'overstock',
    'alibaba',
    'aliexpress',
    'taobao',
    'sears',
    'etsy',
    'newegg'
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
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += 20
    return score


def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain)
            if score > 75:
                tqdm.tqdm.write(
                    "\033[91mSuspicious: "
                    "\033[4m{}\033[0m\033[91m (score={})\033[0m".format(domain,
                                                                        score))
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))
            elif score > 65:
                tqdm.tqdm.write(
                    "Potential: "
                    "\033[4m{}\033[0m\033[0m (score={})".format(domain, score))


certstream.listen_for_events(callback)
