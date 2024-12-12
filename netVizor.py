import subprocess
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Your port list
WELL_KNOWN_PORTS_1_1024 = list(range(1, 1025))
ADDITIONAL_WELL_KNOWN_PORTS = [
    1701, 1723, 3306, 3389, 5900, 8080, 8443,
    9000, 10000, 2049, 3128, 3690, 5000, 5432, 6379, 9200, 9300, 11211,
    27017, 27018, 27019, 50000, 50001
]
WELL_KNOWN_PORTS = WELL_KNOWN_PORTS_1_1024 + ADDITIONAL_WELL_KNOWN_PORTS

# Your scanning functions
def get_mac_address(ip):
    try:
        subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True)
        result = subprocess.run(["getmac", "/s", ip], capture_output=True, text=True)
        output = result.stdout.strip().split("\n")
        if output:
            for line in output:
                mac_address = line.split()[0]
                if mac_address != "Physical":
                    return mac_address
    except Exception:
        pass
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        for line in lines:
            if ip in line:
                return line.split()[1]
    except Exception:
        pass
    return None

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return ip

def scan_ports(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(lambda port: scan_port(ip, port), ports)
        open_ports = [port for port in results if port is not None]
    return open_ports

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception as e:
        print(f"Error scanning port {port} on {ip}: {e}")
    return None

def scan_network(subnet):
    scanned_results = {}
    try:
        for ip in ipaddress.IPv4Network(subnet, strict=False):
            ip_str = str(ip)
            hostname = get_hostname(ip_str)
            mac_address = get_mac_address(ip_str)
            open_ports = scan_ports(ip_str, WELL_KNOWN_PORTS)
            if open_ports:
                scanned_results[ip_str] = {
                    "hostname": hostname,
                    "mac_address": mac_address,
                    "open_ports": open_ports
                }
    except Exception as e:
        print(f"Error scanning network: {e}")
    return scanned_results

def scan_single_ip(ip):
    hostname = get_hostname(ip)
    mac_address = get_mac_address(ip)
    open_ports = scan_ports(ip, WELL_KNOWN_PORTS)
    
    return {
        'host': ip,
        'hostname': hostname,
        'mac_address': mac_address,
        'open_ports': open_ports
    }

# Routes for Flask
