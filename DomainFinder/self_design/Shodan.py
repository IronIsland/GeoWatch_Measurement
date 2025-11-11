import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import re
import os
import concurrent.futures
import requests
def extract_domain_from_text(text):
    domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z]+)+)'
    
    matches = re.findall(domain_pattern, text)
    if matches:
        valid_domains = {domain for domain in matches if not domain.endswith(('.js', '.css', '.ico'))}
        return valid_domains  
    else:
        return set()
def get_subdomains_shodan(domain):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    response = requests.get(f"https://beta.shodan.io/search/facet?query={domain}&facet=domain",headers=headers)
    domains=set()
    if response.status_code == 200:
        domains = extract_domain_from_text(response.text)
    return domains