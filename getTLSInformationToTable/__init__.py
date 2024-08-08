import ssl
import sys
import socket
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
def check_tls_validity(url):
    hostname = urlparse(url).hostname
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    conn.close()
    return ssl_info



def main():
    url = sys.argv[1]
    print(f"Checking TLS information for {url}")
    ssl_info = check_tls_validity(url)
    if ssl_info:
        print(ssl_info)
    else:
        print("No TLS information found")


if __name__ == "__main__":
    main()