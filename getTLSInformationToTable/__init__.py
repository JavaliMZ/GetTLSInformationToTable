import ssl
import sys
import socket
import json
import subprocess
from pprint import pprint
from datetime import datetime
from urllib.parse import urlparse


# Basic Command:
# tlsx -u https://www.google.com -ex -ss -mm -re -un -ve -ce -ct all -o /tmp/tlsx_output.csv

def try_except(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Error when run this function: {func.__name__}")
            print(f"Error: {e}")
    return wrapper

def read_json_file(file):
    content = open(file, "r").read()
    return json.loads(content)

@try_except
def get_tls_validity(url):
    hostname = urlparse(url).hostname
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    conn.close()
    if not ssl_info:
        return None
    ssl_info_dict = {
        "subject": ssl_info["subject"],
        "notBefore": ssl_info["notBefore"],
        "notAfter": ssl_info["notAfter"],
    }
    return ssl_info_dict

@try_except
def get_system_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output, error

def main():
    list_of_urls_file = sys.argv[1]
    command = f"tlsx -l {list_of_urls_file} -j -ex -ss -mm -re -un -ve -ce -ct all -o /tmp/{list_of_urls_file}.result.tlsx.output"
    output, error = get_system_command(command)
    pprint(output)
    pprint(error)



if __name__ == "__main__":
    main()

# main()