import asyncio
from random import randint
from ipaddress import IPv4Network, IPv4Address
import os
from collections.abc import Iterator
import socket
from concurrent.futures import ThreadPoolExecutor
import requests

def generate_ips(path: str) -> Iterator[str]:
    """
    This function is a generator, and will yield an infinite amount of IPv4 addresses.

    IPv4 addresses _already generated_ are in a file `path`, separated by newlines. Those addresses, are not to be yielded again, similar to `excluded`. File integrity is not verified, and the file will be created, and appended into, if it does not exist.
    """
    excluded = [
        IPv4Network("192.168.0.0/16"),
        IPv4Network("153.31.0.0/16"),
        IPv4Network("198.18.0.0/15"),
        IPv4Network("213.248.192.0/24"),
        IPv4Network("195.130.0.0/22"),
        IPv4Network("25.0.0.0/24"),
        IPv4Network("169.254.0.0/16"),
        IPv4Network("172.9.0.0/24"),
        IPv4Network("100.64.0.0/10"),
        IPv4Network("15.0.0.0/8"),
        IPv4Network("172.16.0.0/14"),
        IPv4Network("56.0.0.0/8"),
        IPv4Network("3.0.0.0/8"),
        IPv4Network("127.0.0.0/8"),  # Localhost
        IPv4Network("10.0.0.0/8"),  # Private network
        IPv4Network("192.168.0.0/16"),  # Private network
        IPv4Network("172.16.0.0/12"),  # Private network
    ]

    # make sure the file exists
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.path.exists(path) or open(path, "w").close()

    # read the file into memory
    with open(path, "r") as read_file:
        previous = set(read_file.read().splitlines())

    # yield, and append to the file
    with open(path, "a") as append_file:
        while True:
            # this works right now because there is an address space of
            # 256 ^ 4 - EXCLUDED_V4_IPS
            byte = lambda: randint(0, 255)
            four_bytes = f"{byte()}.{byte()}.{byte()}.{byte()}"
            ip_address = IPv4Address(four_bytes)

            skip = False

            if ip_address in previous:
                skip = True
            for ip_addresses in excluded:
                if ip_address in ip_addresses:
                    skip = True

            if not skip:
                previous.add(ip_address)
                append_file.write(f"{ip_address}\n")
                append_file.flush()

                # https://docs.python.org/3/glossary.html#term-generator-iterator
                yield str(ip_address)



async def scan_port(ip: str, port: int):
    """
    This function will attempt to perform a SYN scan on a TCP port of an IPv4 address.
    """

    timeout = 1  # Set your desired timeout

    def syn_scan(ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            banner = get_banner(sock)
            sock.close()
            if "SSH" in banner:
                return True,banner
        except (socket.timeout, socket.error):
            return False,False
        finally:
            sock.close()
            

    def get_banner(sock):
        try:
            banner = sock.recv(1024).decode('utf-8').strip()
            return banner
        except Exception as e:
            return str(e)
        finally:
            sock.close()

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(ThreadPoolExecutor(), syn_scan, ip, port)
    if result == None: return False
    if result[0]:
        print(f"{ip}:{port} is open\n Info about system {result[1]}")
        with open("./out/ssh_ips.log", "a") as log_file:
            log_file.write(f"{ip}:{port}" + "\n")


async def main():
    path = "./out/ips.log"
    start = 22
    end = 22

    coros = []
    coros_batch_size = 1024 * 1.5 # if network is slow, lower this number

    print("scanning for IPv4 TCP ports...", flush=True)
    print("https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers", flush=True)
    print("press CTRL+C to stop\n", flush=True)

    for ip in generate_ips(path):
        for port in range(start, end):
            coros.append(scan_port(ip, port))

            if len(coros) == coros_batch_size:
                await asyncio.gather(*coros)
                coros = []

# TODO make it run ipconfig /release and ipconfig /renew 
if __name__ == "__main__":
    asyncio.run(main())
