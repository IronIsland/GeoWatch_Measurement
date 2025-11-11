import sys
import os
import pathlib
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import re
import os
import concurrent.futures
import time
import tldextract

def extract_domain_from_text(text):
    domain_pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z]+)+)'
    
    matches = re.findall(domain_pattern, text)
    if matches:
        return matches[0]  
    else:
        return None
def webdriver_integrate(domain):
    subdomains=set()
    extracted = tldextract.extract(domain)
    driver = webdriver.Chrome()
    driver.get(f"https://www.whoxy.com/keyword/{extracted.domain}")

    tables = driver.find_elements(By.TAG_NAME, "table")
    if tables:
        table = tables[1]  
        rows = table.find_elements(By.TAG_NAME, "tr")
        for row in rows:
            try:
                cell = row.find_element(By.CSS_SELECTOR, "td.left.nowrap > a")
                subdomain_text = cell.text
                subdomains.add(subdomain_text)
            except Exception:
                pass
    driver.quit()
    return subdomains
