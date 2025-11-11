import sys
import os
import time
import subprocess


def call_JSFinder(domain,output,threads):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    jsfinder_script_path = os.path.join(current_dir, 'thirdparty', 'JSFinder', 'JSFinder.py')
    dir = "results/{}".format(domain)
    if not os.path.exists(dir):
        os.makedirs(dir)
    
    url = "https://"+ domain
    command = [
        "python", jsfinder_script_path,
        "-u",url,
        # "-d",
        "-t",str(threads),
        "-os",output
    ]

    subprocess.run(command)

import time
