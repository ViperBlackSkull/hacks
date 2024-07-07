import socket
import ipaddress
import threading
import argparse
from queue import Queue
from tqdm import tqdm

def check_udp_dns_server(ip, alive_servers):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        message = b'\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'
        sock.sendto(message, (ip, 53))
        sock.recvfrom(512)
        alive_servers.append(ip)
    except socket.timeout:
        pass  # DNS server not responding
    except Exception:
        pass  # DNS server not responding
    finally:
        sock.close()

def worker(ip_queue, alive_servers, progress_bar):
    while not ip_queue.empty():
        ip = ip_queue.get()
        check_udp_dns_server(str(ip), alive_servers)
        ip_queue.task_done()
        progress_bar.update(1)

def find_alive_dns_servers(ip_ranges, num_threads=50):
    ip_queue = Queue()
    alive_servers = []

    total_ips = 0
    for ip_range in ip_ranges:
        try:
            network = ipaddress.IPv4Network(ip_range, strict=False)
            total_ips += network.num_addresses
            for ip in network:
                ip_queue.put(ip)
        except ValueError as e:
            print(f"Invalid IP range {ip_range}: {e}")

    progress_bar = tqdm(total=total_ips, desc="Scanning", unit="ip")

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(ip_queue, alive_servers, progress_bar))
        thread.start()
        threads.append(thread)

    ip_queue.join()

    for thread in threads:
        thread.join()

    progress_bar.close()
    return alive_servers

def load_ip_ranges_from_file(file_path):
    with open(file_path, 'r') as file:
        ip_ranges = [line.strip() for line in file if line.strip()]
    return ip_ranges

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find alive DNS servers in given IP ranges.")
    parser.add_argument("-r", "--ip_ranges", nargs='+', help="The IP ranges to scan (e.g., 192.168.1.0/24 10.0.0.0/8)")
    parser.add_argument("-i", "--input", help="File containing a list of IP ranges to scan, one per line")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads to use for scanning")
    parser.add_argument("-o", "--output", help="File to output the list of working DNS servers")

    args = parser.parse_args()

    if args.ip_ranges:
        ip_ranges = args.ip_ranges
    elif args.input:
        ip_ranges = load_ip_ranges_from_file(args.input)
    else:
        print("Either --ip_ranges or --input must be provided.")
        exit(1)

    alive_servers = find_alive_dns_servers(ip_ranges, args.threads)

    if args.output:
        with open(args.output, 'w') as f:
            for server in alive_servers:
                f.write(f"{server}\n")
        print(f"Alive DNS servers saved to {args.output}")
    else:
        print(f"Alive DNS servers: {alive_servers}")
