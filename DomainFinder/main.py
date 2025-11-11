#!/usr/bin/python3
# coding=utf-8
import sys
import os
import subprocess
from pathlib import Path
import utils.util
import asyncio
from concurrent.futures import ThreadPoolExecutor

from call_brute import call_brute_all
from call_collect import call_oneforall
import call_jsfinder
from call_jsfinder import call_JSFinder
from loguru import logger
import self_design.collect
import self_design.Chaziyu

import time

def merge_all_subdomains(domain):

    result_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results', domain)
    subdomains = set()
    if not os.path.exists(result_folder):
        logger.error(f"Result folder {result_folder} does not exist.")
        return
    for filename in os.listdir(result_folder):
        if filename.endswith('.txt') and filename != 'all_subdomains.txt':
            with open(os.path.join(result_folder, filename), 'r', encoding='utf-8') as f:
                for line in f:
                    sub = line.strip()
                    if sub:
                        subdomains.add(sub)
    all_file = os.path.join(result_folder, 'all_subdomains.txt')
    with open(all_file, 'w', encoding='utf-8') as f:
        for sub in sorted(subdomains):
            f.write(sub + '\n')
    logger.log('INFOR', f'Aggregation complete. Found {len(subdomains)} subdomains for {domain}, saved to all_subdomains.txt')

def get_domains_from_file(file_path):

    current_file_path = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(file_path):
        file_path = os.path.join(current_file_path, file_path)

    if os.path.isfile(file_path) and file_path.endswith('.txt'):
        return utils.util.get_domains(target="",targets=file_path)
    elif os.path.isdir(file_path):
        domains = []
        for file in os.listdir(file_path):
            if file.endswith('.txt'):
                # print(file)
                domains.extend(utils.util.get_domains(target="",targets=os.path.join(file_path,file)))
        return domains
    else:
        logger.error(f"Invalid file or directory: {file_path}")
        return []

async def process_domain(domain, results_path):
    
    if os.path.exists(os.path.join(results_path)):
        logger.log('INFOR', f'Skipping {domain}, already processed.')
        return


    os.makedirs(results_path, exist_ok=True)

    brute_output = os.path.join(results_path, 'brute.txt')
    if os.path.exists(brute_output):
        logger.log('INFOR', f'Skipping {domain}, already processed.')
        return
    
    start_time = time.time()
    logger.log('INFOR', f'Start Collecting {domain}')
    call_brute_all(domain, full=True, threads=5000, process=10, output=brute_output)

    call_oneforall(domain)

    call_JSFinder(domain=domain, output=os.path.join(results_path, "JSFinder.txt"), threads=1000)

    # self_design.collect.collect_all(domain,results_path)

    end_time = time.time()
    merge_all_subdomains(domain)
    logger.log('INFOR', f'Finished Collecting {domain}, Using {end_time-start_time} seconds')

async def main():
    target_file = sys.argv[1]  
    current_file_path = os.path.dirname(os.path.abspath(__file__))
    results_path = os.path.join(current_file_path,'results')

    domains = get_domains_from_file(target_file)

    with ThreadPoolExecutor(max_workers=5) as executor:
        await asyncio.gather(*[process_domain(domain, os.path.join(results_path, domain)) for domain in domains])



if __name__ == "__main__":
    asyncio.run(main())
