import json
import sys
import subprocess
from tabulate import tabulate  # type: ignore
from datetime import datetime


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

def get_date(string):
    date_object = datetime.strptime(string, "%Y-%m-%dT%H:%M:%SZ")
    formatted_date = date_object.strftime("%d%b%Y UTC").upper()
    return formatted_date

@try_except
def get_all_data(data):
    json_data = json.loads(data)
    host = json_data["host"]
    port = json_data["port"]
    ip = json_data["ip"]
    not_before = get_date(json_data["not_before"])
    not_after = get_date(json_data["not_after"])
    ciphers = json_data["cipher_enum"]
    cipher_problem = []
    for cipher in ciphers:
        version = cipher["version"]
        has_insecure_cipher = "insecure" in cipher["ciphers"].keys()
        has_weak_cipher = "weak" in cipher["ciphers"].keys()
        has_unknown_cipher = "unknown" in cipher["ciphers"].keys()
        if has_insecure_cipher:
            cipher_problem.append([version, "insecure", cipher["ciphers"]["insecure"]])
        if has_weak_cipher:
            cipher_problem.append([version, "weak", cipher["ciphers"]["weak"]])
        if has_unknown_cipher:
            cipher_problem.append([version, "unknown", cipher["ciphers"]["unknown"]])
    
    return [
        host,
        ip,
        port,
        not_before,
        not_after,
        cipher_problem
    ]

def print_table(all_data):
    table = [line for line in all_data]
    print(tabulate(table, tablefmt='plain', numalign="left"))

def check_for_tslx_installed():
    command = "tlsx --version"
    output, error = get_system_command(command)
    if error:
        print("tlsx is not installed")
        sys.exit(1)
    print("tlsx is installed")


@try_except
def main():
    check_for_tslx_installed()
    list_of_urls_file = sys.argv[1]
    output_path = f"/tmp/{list_of_urls_file}.result.tlsx.output"
    command = f"tlsx -l {list_of_urls_file} -j -ex -ss -mm -re -un -ve -ce -ct all -o {output_path}"
    output, error = get_system_command(command)
    all_data = []
    with open(output_path) as json_file:
        for data in json_file:
            all_data.append(get_all_data(data))
    
    print_table(all_data)




if __name__ == "__main__":
    main()

# main()