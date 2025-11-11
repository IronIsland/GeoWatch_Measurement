import sys
import os
import time
import subprocess


def call_brute_all(target, full=False, threads=500, process=6, output=None):

    current_dir = os.path.dirname(os.path.abspath(__file__))
    brute_script_path = os.path.join(current_dir, 'thirdparty', 'subDomainsBrute', 'subDomainsBrute.py')
    command = [
        "python", brute_script_path,
        target,
    ]
    if full:
        command.append("--full")
    command.extend(["-t", str(threads)])
    command.extend(["-p", str(process)])

    if output:
        command.extend(["-o", output])
    subprocess.run(command)

# call_brute("baidu.com", full=True, threads=5000, process=10, output=results_path)