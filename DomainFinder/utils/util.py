import os
import re
import sys
import pathlib

util_path = pathlib.Path(__file__).parent.parent.joinpath("utils")
# print(util_path)
sys.path.append(util_path)

import time
import json
import socket
import random
import string
import platform
import subprocess
from urllib.parse import scheme_chars
from ipaddress import IPv4Address, ip_address
from distutils.version import LooseVersion
from pathlib import Path
from stat import S_IXUSR

import requests
import tenacity
from dns.resolver import Resolver

from utils.domain import Domain
from utils.log import logger

import re
def match_subdomains(domain, html, distinct=True, fuzzy=True):
    """
    Use regexp to match subdomains

    :param  str domain: main domain
    :param  str html: response html text
    :param  bool distinct: deduplicate results or not (default True)
    :param  bool fuzzy: fuzzy match subdomain or not (default True)
    :return set/list: result set or list
    """
    # logger.log('TRACE', f'Use regexp to match subdomains in the response body')
    if fuzzy:
        regexp = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' \
                 + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
        if not result:
            return set()
        deal = map(lambda s: s.lower(), result)
        if distinct:
            return set(deal)
        else:
            return list(deal)
    else:
        regexp = r'(?:\>|\"|\'|\=|\,)(?:http\:\/\/|https\:\/\/)?' \
                 r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' \
                 + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
    if not result:
        return set()
    regexp = r'(?:http://|https://)'
    deal = map(lambda s: re.sub(regexp, '', s[1:].lower()), result)
    if distinct:
        return set(deal)
    else:
        return list(deal)
    
def extract_domain_from_text(text):
    domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z]+)+)'
    
    matches = re.findall(domain_pattern, text)
    if matches:
        valid_domains = {domain for domain in matches if not domain.endswith(('.js', '.css', '.ico'))}
        return valid_domains 
    else:
        return set()

IP_RE = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')  # pylint: disable=line-too-long
SCHEME_RE = re.compile(r'^([' + scheme_chars + ']+:)?//')
def match_main_domain(domain):
    if not isinstance(domain, str):
        return None
    item = domain.lower().strip()
    return Domain(item).match()


def read_target_file(target):
    domains = list()
    with open(target, encoding='utf-8', errors='ignore') as file:
        for line in file:
            domain = match_main_domain(line)
            if not domain:
                continue
            domains.append(domain)
    sorted_domains = sorted(set(domains), key=domains.index)
    return sorted_domains


def get_from_target(target):
    domains = set()
    if isinstance(target, str):
        if target.endswith('.txt'):
            logger.log('FATAL', 'Use targets parameter for multiple domain names')
            exit(1)
        domain = match_main_domain(target)
        if not domain:
            return domains
        domains.add(domain)
    return domains


def get_from_targets(targets):
    domains = set()
    if not isinstance(targets, str):
        return domains
    try:
        path = Path(targets)
    except Exception as e:
        logger.log('ERROR', e.args)
        return domains
    if path.exists() and path.is_file():
        domains = read_target_file(targets)
        return domains
    return domains


def get_domains(target, targets=None):
    logger.log('DEBUG', f'Getting domains')
    target_domains = get_from_target(target)
    targets_domains = get_from_targets(targets)
    domains = list(target_domains.union(targets_domains))
    if targets_domains:
        domains = sorted(domains, key=targets_domains.index) 
    if not domains:
        logger.log('ERROR', f'Did not get a valid domain name')
    logger.log('DEBUG', f'The obtained domains \n{domains}')
    return domains



def looks_like_ip(maybe_ip):
    """Does the given str look like an IP address?"""
    if not maybe_ip[0].isdigit():
        return False

    try:
        socket.inet_aton(maybe_ip)
        return True
    except (AttributeError, UnicodeError):
        if IP_RE.match(maybe_ip):
            return True
    except socket.error:
        return False
    
    
def match_subdomains(domain, html, distinct=True, fuzzy=True):
    """
    Use regexp to match subdomains

    :param  str domain: main domain
    :param  str html: response html text
    :param  bool distinct: deduplicate results or not (default True)
    :param  bool fuzzy: fuzzy match subdomain or not (default True)
    :return set/list: result set or list
    """
    logger.log('TRACE', f'Use regexp to match subdomains in the response body')
    if fuzzy:
        regexp = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' \
                 + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
        if not result:
            return set()
        deal = map(lambda s: s.lower(), result)
        if distinct:
            return set(deal)
        else:
            return list(deal)
    else:
        regexp = r'(?:\>|\"|\'|\=|\,)(?:http\:\/\/|https\:\/\/)?' \
                 r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' \
                 + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
    if not result:
        return set()
    regexp = r'(?:http://|https://)'
    deal = map(lambda s: re.sub(regexp, '', s[1:].lower()), result)
    if distinct:
        return set(deal)
    else:
        return list(deal)