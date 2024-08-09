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

@try_except
def get_date(string):
    date_object = datetime.strptime(string, "%Y-%m-%dT%H:%M:%SZ")
    formatted_date = date_object.strftime("%d%b%Y").upper()
    return formatted_date

@try_except
def get_all_data(data):
    parsed_data = []
    json_data = json.loads(data)
    host = json_data["host"]
    port = json_data["port"]
    ip = json_data["ip"]
    not_before = get_date(json_data["not_before"])
    not_after = get_date(json_data["not_after"])
    parsed_data.append([host, port, ip, not_before, not_after, "", "", ""])
    ciphers = json_data["cipher_enum"]
    for cipher in ciphers:
        version = cipher["version"]
        has_insecure_cipher = "insecure" in cipher["ciphers"].keys()
        has_weak_cipher = "weak" in cipher["ciphers"].keys()
        has_unknown_cipher = "unknown" in cipher["ciphers"].keys()
        if has_insecure_cipher:
            for c in cipher['ciphers']['insecure']:
                parsed_data.append([host, port, ip, not_before, not_after, version, "insecure", c])
        if has_weak_cipher:
            for c in cipher['ciphers']['weak']:
                parsed_data.append([host, port, ip, not_before, not_after, version, "weak", c])
        if has_unknown_cipher:
            for c in cipher['ciphers']['unknown']:
                parsed_data.append([host, port, ip, not_before, not_after, version, "unknown", c])
    
    return parsed_data

@try_except
def print_table(all_data):
    table = [line for data in all_data for line in data]
    print(tabulate(table, tablefmt='plain', numalign="left"))


@try_except
def main():
    if sys.argv[1] == "-h":
        print("tlsx -l domains.txt -j -ex -ss -mm -re -un -ve -ce -ct all -o result.json\n\n")
        print("run this command to get the result in table format")
        print("getTLSInformationToTable result.json")
        sys.exit(0)
    json_file_path = sys.argv[1]
    all_data = []
    with open(json_file_path) as json_file:
        for data in json_file:
            all_data.append(get_all_data(data))
    
    print_table(all_data)




if __name__ == "__main__":
    main()

# main()