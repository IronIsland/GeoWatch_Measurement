from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import re
import os
import concurrent.futures
import requests
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
def get_subdomains_chaziyu(domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    response = requests.get(f"https://chaziyu.com/{domain}",headers=headers)
    domains=list()
    if response.status_code == 200:
        # print(response.text)
        # soup = BeautifulSoup(response.text, 'html.parser')
        domains = match_subdomains(domain,response.text)
        # print(domains)
    return domains
    