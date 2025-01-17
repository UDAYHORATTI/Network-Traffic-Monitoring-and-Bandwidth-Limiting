# Network-Traffic-Monitoring-and-Bandwidth-Limiting
This script monitors the traffic on a network, logs the usage for each IP address, and enforces a bandwidth limit by controlling the amount of data a device can send or receive.
import scapy.all as scapy
import time
import subprocess
import threading
from collections import defaultdict

# Configuration
NETWORK_INTERFACE = "eth0"  # Network interface for monitoring
BANDWIDTH_LIMIT_MB = 50  # Maximum bandwidth per device in MB (per minute)
LOG_FILE = "bandwidth_usage.log"  # Log file for bandwidth tracking
CHECK_INTERVAL = 60  # Time interval to check bandwidth usage in seconds

# Setting up logging
import logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionary to store data usage for each IP address
data_usage = defaultdict(lambda: {'bytes_in': 0, 'bytes_out': 0, 'blocked': False})

# Function to log bandwidth usage
def log_usage(ip, direction, packet_size):
    if direction == "in":
        data_usage[ip]['bytes_in'] += packet_size
    elif direction == "out":
        data_usage[ip]['bytes_out'] += packet_size
    logging.info(f"IP: {ip}, Direction: {direction}, Size: {packet_size} bytes")

# Function to block an IP if it exceeds the bandwidth limit
def block_ip(ip):
    if not data_usage[ip]['blocked']:
        subprocess.run(["iptables", "-A", "OUTPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        data_usage[ip]['blocked'] = True
        print(f"Blocked IP: {ip} for exceeding bandwidth limit")

# Function to unblock an IP
def unblock_ip(ip):
    if data_usage[ip]['blocked']:
        subprocess.run(["iptables", "-D", "OUTPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        data_usage[ip]['blocked'] = False
        print(f"Unblocked IP: {ip}")

# Function to track incoming and outgoing packets
def packet_handler(packet):
    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dest_ip = packet[scapy.IP].dst
            packet_size = len(packet)

            # Log incoming traffic
            if packet[scapy.IP].dst == dest_ip:
                log_usage(dest_ip, "in", packet_size)

            # Log outgoing traffic
            if packet[scapy.IP].src == src_ip:
                log_usage(src_ip, "out", packet_size)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Function to check the bandwidth usage and enforce limits
def enforce_bandwidth_limit():
    while True:
        time.sleep(CHECK_INTERVAL)
        for ip, usage in data_usage.items():
            total_usage_mb = (usage['bytes_in'] + usage['bytes_out']) / (1024 * 1024)
            if total_usage_mb > BANDWIDTH_LIMIT_MB and not usage['blocked']:
                block_ip(ip)
            elif total_usage_mb <= BANDWIDTH_LIMIT_MB and usage['blocked']:
                unblock_ip(ip)
                usage['bytes_in'], usage['bytes_out'] = 0, 0  # Reset usage after unblocking

# Function to start monitoring traffic
def start_sniffing():
    print("Starting network traffic monitoring...")
    scapy.sniff(iface=NETWORK_INTERFACE, prn=packet_handler, store=0)

# Function to start the monitoring system
def run_monitoring():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    while True:
        time.sleep(CHECK_INTERVAL)
        display_usage()

# Function to display the current bandwidth usage
def display_usage():
    print("Bandwidth Usage Summary:")
    print("-" * 50)
    for ip, usage in data_usage.items():
        total_usage_mb = (usage['bytes_in'] + usage['bytes_out']) / (1024 * 1024)  # Convert bytes to MB
        print(f"IP Address: {ip}")
        print(f"  - Incoming Traffic: {usage['bytes_in'] / (1024 * 1024):.2f} MB")
        print(f"  - Outgoing Traffic: {usage['bytes_out'] / (1024 * 1024):.2f} MB")
        print(f"  - Total Traffic: {total_usage_mb:.2f} MB")
        if usage['blocked']:
            print(f"  - Status: BLOCKED")
        else:
            print(f"  - Status: OK")
        print("-" * 50)

# Main execution
if __name__ == "__main__":
    run_monitoring()
