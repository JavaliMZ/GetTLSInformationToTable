import json
import sys
import subprocess
from tabulate import tabulate  # type: ignore
from datetime import datetime
from termcolor import colored  # type: ignore
from pwn import log

# Basic Command:
# tlsx -u https://www.google.com -ex -ss -mm -re -un -ve -ce -ct all -o /tmp/tlsx_output.csv

def try_except(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Error when run this function: {func.__name__}")
            print(f"Error: {e}")
            sys.exit(1)
    return wrapper


@try_except
def get_system_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output, error

@try_except
def get_date(string):
    date_object = datetime.strptime(string, "%Y-%m-%dT%H:%M:%SZ")
    formatted_date = date_object.strftime("%d%b%Y").upper()
    return formatted_date

@try_except
def execute_tls_scan(host):
    command = f"$HOME/go/bin/check-tls-cert net -H {host}"
    output, error = get_system_command(command)
    if error:
        print(f"Error when execute command: {command}")
        print(f"Error: {error}")
        sys.exit(1)
    return output.decode()

@try_except
def get_length_insecure_and_weak_cipher(cipher_list):
    length = 0
    for cipher in cipher_list:
        if "insecure" in cipher["ciphers"].keys():
            length += len(cipher["ciphers"]["insecure"])
        if "weak" in cipher["ciphers"].keys():
            length += len(cipher["ciphers"]["weak"])
    return length


@try_except
def get_all_data(data, log_info):
    parsed_data = []
    json_data = json.loads(data)
    host = json_data["host"]
    port = json_data["port"]
    ip = json_data["ip"]
    not_before = get_date(json_data["not_before"])
    not_after = get_date(json_data["not_after"])
    ciphers = json_data["cipher_enum"]
    length_insecure_and_weak_cipher = get_length_insecure_and_weak_cipher(ciphers)
    log_info.status(f"Get data from {host}:{port}")
    res_tls_scan = execute_tls_scan(host)
    if length_insecure_and_weak_cipher == 0:
            parsed_data.append([
                colored(host, "green"), 
                colored(ip, "magenta"), 
                port, 
                not_before, 
                colored(not_after, "cyan"), 
                    res_tls_scan

            ])
    else:
        if not "OK" in res_tls_scan:
            parsed_data.append([
                colored(host, "green"), 
                colored(ip, "magenta"), 
                port, 
                not_before, 
                colored(not_after, "cyan"), 
                res_tls_scan

            ])
    if length_insecure_and_weak_cipher > int(sys.argv[2]):
        parsed_data.append([
            colored(host, "green"), 
            colored(ip, "magenta"), 
            port, 
            not_before, 
            colored(not_after, "cyan"), 
            f"{colored('To many insecure or weak ciphers available', 'red')}"
            ])
        return parsed_data
    
    for cipher in ciphers:
        version = cipher["version"]
        has_insecure_cipher = "insecure" in cipher["ciphers"].keys()
        has_weak_cipher = "weak" in cipher["ciphers"].keys()

        if has_insecure_cipher:
            for c in cipher['ciphers']['insecure']:
                parsed_data.append([
                    colored(host, "green"), 
                    colored(ip, "magenta"), 
                    port, 
                    not_before, 
                    colored(not_after, "cyan"), 
                    f"{version} - {colored('insecure', 'red')} {colored(c, 'yellow')}"
                    ])
        if has_weak_cipher:
            for c in cipher['ciphers']['weak']:
                parsed_data.append([
                    colored(host, "green"), 
                    colored(ip, "magenta"), 
                    port, 
                    not_before, 
                    colored(not_after, "cyan"), 
                    f"{version} - {colored('weak', 'red')} {colored(c, 'yellow')}"
                    ])
    
    return parsed_data

@try_except
def print_table(all_data):
    table = [line for data in all_data for line in data]
    print(tabulate(table, tablefmt='presto', numalign="left"))


@try_except
def main():
    log_info = log.progress("Get all data")
    if sys.argv[1] == "-h":
        print("Prepare a single json file:")
        print("[+] tlsx -l domains.txt -j -ex -ss -mm -re -un -ve -ce -ct all -o result.json\n\n")
        print("run this command to get the result in table format")
        print("[+] getTLSInformationToTable result.json <length of insecure and weak ciphers>")
        sys.exit(0)
    json_file_path = sys.argv[1]
    all_data = []
    with open(json_file_path) as json_file:
        for data in json_file:
            all_data.append(get_all_data(data, log_info))
    
    print_table(all_data)




if __name__ == "__main__":
    main()

# main()