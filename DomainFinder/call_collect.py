import subprocess
import os
def call_oneforall(target):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    oneforall_script_path = os.path.join(current_dir, 'thirdparty', 'OneForAll', 'modules','collect.py')
    command = [
        "python", oneforall_script_path,
        "--target", target
    ]
    subprocess.run(command)
# call_oneforall("example.com")
