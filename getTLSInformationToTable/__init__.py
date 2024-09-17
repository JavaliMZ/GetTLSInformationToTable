import json
import sys
import subprocess
from tabulate import tabulate  # type: ignore
from datetime import datetime
from termcolor import colored  # type: ignore
from pwn import log

def try_except(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Error when running the function: {func.__name__}")
            print(f"Error: {e}")
            sys.exit(1)
    return wrapper

@try_except
def get_system_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    return output, error

@try_except
def format_date(date_str):
    date_object = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
    return date_object.strftime("%d%b%Y").upper()

@try_except
def execute_tls_scan(host):
    # return "OK: All checks passed"
    command = f"$HOME/go/bin/check-tls-cert net -H {host}"
    output, error = get_system_command(command)
    if error:
        log.error(f"Error executing command: {command}")
        print(f"Error: {error}")
        sys.exit(1)
    return output.decode()

@try_except
def count_insecure_weak_ciphers(cipher_list):
    return sum(len(cipher["ciphers"].get("insecure", [])) + len(cipher["ciphers"].get("weak", [])) for cipher in cipher_list)

@try_except
def parse_line_info(parsed_data, tls_data_host, description):
    parsed_data.append([
        colored(tls_data_host["host"], "green"), 
        colored(tls_data_host["ip"], "magenta"), 
        tls_data_host["port"], 
        tls_data_host["not_before"], 
        colored(tls_data_host["not_after"], "cyan"), 
        description
    ])

@try_except
def parse_single_cipher(parsed_data, tls_data_host, version, cipher_type, cipher_list):
    for c in cipher_list:
        description = f"{version} - {colored(cipher_type, 'red')} {colored(c, 'yellow')}"
        parse_line_info(parsed_data, tls_data_host, description)


@try_except
def parse_ciphers(tls_data_host, ciphers):
    parsed_data = []
    for cipher in ciphers:
        version = cipher["version"]
        for cipher_type in ["insecure", "weak"]:
            if cipher_type in cipher["ciphers"]:
                parse_single_cipher(parsed_data, tls_data_host, version, cipher_type, cipher["ciphers"][cipher_type])
    return parsed_data

@try_except
def parse_tls_data(data, log_info):
    json_data = json.loads(data)
    host, port, ip = json_data["host"], json_data["port"], json_data["ip"]
    not_before, not_after = format_date(json_data["not_before"]), format_date(json_data["not_after"])
    ciphers = json_data["cipher_enum"]

    log_info.status(f"Get data from {host}:{port}")

    insecure_weak_cipher_count = count_insecure_weak_ciphers(ciphers)
    description = execute_tls_scan(host)
    tls_data_host = {
        "host": host,
        "port": port,
        "ip": ip,
        "not_before": not_before,
        "not_after": not_after
    }

    parsed_data = []
    if insecure_weak_cipher_count == 0 or "OK" not in description:
        description = description.replace("OK", colored("OK", "green"))
        description = description.replace("CRITICAL", colored("CRITICAL", "yellow"))
        parse_line_info(parsed_data, tls_data_host, description)

    if insecure_weak_cipher_count > int(sys.argv[2]):
        description = colored('Too many insecure or weak ciphers available', "red")
        parse_line_info(parsed_data, tls_data_host, description)
    else:
        parsed_data.extend(parse_ciphers(tls_data_host, ciphers))

    return parsed_data

@try_except
def print_table(data):
    table = [line for dataset in data for line in dataset]
    print(tabulate(table, tablefmt='presto', numalign="left"))

@try_except
def print_tab():
    print("\t", end="")

@try_except
def main():
    if sys.argv[1] == "-h":
        log.warn("Prepare a single JSON file:")
        print_tab()
        log.info("tlsx -l domains.txt -j -ex -ss -mm -re -un -ve -ce -ct all -o result.json\n\n")
        log.warn("Run this command to get the result in table format")
        print_tab()
        log.info("getTLSInformationToTable result.json <length_of_insecure_and_weak_ciphers>")
        sys.exit(0)
    
    log_info = log.progress("Get all data")
    json_file_path = sys.argv[1]
    all_data = []
    
    with open(json_file_path) as json_file:
        for line in json_file:
            all_data.append(parse_tls_data(line, log_info))
    
    print_table(all_data)

if __name__ == "__main__":
    main()
