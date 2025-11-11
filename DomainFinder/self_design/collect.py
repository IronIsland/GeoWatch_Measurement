from .Chaziyu import get_subdomains_chaziyu
from .Crtsh import get_subdomains_crtsh
from .Shodan import get_subdomains_shodan
from .integrate import webdriver_integrate
import time
import os
import platform
def collect_all(domain,folder):
    subdomains=set()
    
    subdomains.update(get_subdomains_chaziyu(domain))

    subdomains.update(get_subdomains_crtsh(domain))

    subdomains.update(get_subdomains_shodan(domain))


    path = os.path.join(folder,"Collect.txt")
    with open(path, 'a+') as f:
        for subdomain in subdomains:
            f.write(subdomain + '\n')

    return subdomains
