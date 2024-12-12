import aioping
import asyncio
import socket
import ipaddress
import platform
import subprocess
import re
import socket
from asyncio import Queue

WELL_KNOWN_PORTS = list(range(1, 1025)) + [
    1701, 1723, 3306, 3389, 5900, 8080, 8443, 9000,
    10000, 2049, 3128, 3690, 5000, 5432, 6379, 9200,
    9300, 11211, 27017, 27018, 27019, 50000, 50001
]

async def scan_port_async(ip, port):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_ports_async(ip, ports):
    tasks = [scan_port_async(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)
    return [port for port in results if port is not None]

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def get_mac_address(ip):
    try:
        if platform.system() == "Windows":
            subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True, check=True)
            result = subprocess.run(["getmac", "/s", ip], capture_output=True, text=True)
            mac_address = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", result.stdout)
            
            if mac_address:
                return mac_address.group(0)
            else:
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                output = result.stdout
                for line in output.splitlines():
                    if ip in line:
                        mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", line)
                        if mac:
                            return mac.group(0)
        else:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
            output = result.stdout
            mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
            if mac:
                return mac.group(0)
    except Exception as e:
        print(f"Error retrieving MAC address for {ip}: {e}")
    return None

async def scan_single_ip_async(ip):
    open_ports = await scan_ports_async(ip, WELL_KNOWN_PORTS)
    hostname = get_hostname(ip)
    mac_address = get_mac_address(ip)
    return {
        "host": ip,
        "hostname": hostname,
        "mac_address": mac_address,
        "open_ports": open_ports
    }


async def ping_host_with_queue(ip, queue):
    await queue.put(ip)
    try:
        delay = await aioping.ping(ip, timeout=2)
        return ip if delay is not None else None
    except TimeoutError:
        return None
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return None
    finally:
        queue.get_nowait()

async def scan_network_async_with_queue(subnet):
    reachable_ips = []
    queue = Queue(maxsize=100)
    tasks = [ping_host_with_queue(str(ip), queue) for ip in ipaddress.IPv4Network(subnet, strict=False)]
    
    ping_results = await asyncio.gather(*tasks)
    reachable_ips = [ip for ip in ping_results if ip is not None]
    print(reachable_ips)
    
    results = {}
    scan_tasks = [scan_single_ip_async(ip) for ip in reachable_ips]
    scan_results = await asyncio.gather(*scan_tasks)
    
    for result in scan_results:
        if result and (result["open_ports"] or result["mac_address"]):
            results[result["host"]] = result
    
    return results