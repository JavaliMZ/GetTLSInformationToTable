import ssl
import sys
import socket
from pprint import pprint
from datetime import datetime
from urllib.parse import urlparse


def try_except(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Error: {e}")
    return wrapper


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



def main():
    url = sys.argv[1]
    pprint(f"Checking TLS information for {url}")
    ssl_info = get_tls_validity(url)
    if ssl_info:
        pprint(ssl_info)
    else:
        pprint("No TLS information found")


if __name__ == "__main__":
    main()