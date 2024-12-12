import aioping
import asyncio
import socket
import ipaddress
import platform
import subprocess
import re

WELL_KNOWN_PORTS = list(range(1, 1025)) + [
    1701, 1723, 3306, 3389, 5900, 8080, 8443, 9000,
    10000, 2049, 3128, 3690, 5000, 5432, 6379, 9200,
    9300, 11211, 27017, 27018, 27019, 50000, 50001
]

async def scan_port_async(ip, port, semaphore, timeout=2):
    try:
        async with semaphore:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port
    except:
        return None

async def scan_ports_async(ip, ports, max_concurrent_tasks=500, timeout=2):
    semaphore = asyncio.Semaphore(max_concurrent_tasks)
    
    tasks = [scan_port_async(ip, port, semaphore, timeout) for port in ports]
    results = await asyncio.gather(*tasks)
    return [port for port in results if port is not None]

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def get_mac_address(ip):
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            if ip in line:
                return line.split()[1].upper()

    except Exception as e:
        print(f"Error retrieving MAC address for {ip}: {e}")

    return None

async def ping_host(ip):
    try:
        delay = await aioping.ping(ip, timeout=2)
        return ip if delay is not None else None
    except TimeoutError:
        return None
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return None

async def scan_single_ip_async(ip, semaphore=asyncio.Semaphore(1)):
    try:
        async with semaphore:
            open_ports = await scan_ports_async(ip, WELL_KNOWN_PORTS)
            print(open_ports)
            hostname = get_hostname(ip)
            print(hostname)
            mac_address = get_mac_address(ip)
            print(mac_address)
            return {
                "host": ip,
                "hostname": hostname,
                "mac_address": mac_address,
                "open_ports": open_ports
            }
    except:
        return None

async def scan_network_async(subnet):
    reachable_ips = []
    tasks = [ping_host(str(ip)) for ip in ipaddress.IPv4Network(subnet, strict=False)]
    
    ping_results = await asyncio.gather(*tasks)
    reachable_ips = [ip for ip in ping_results if ip is not None]
    print(reachable_ips)
    
    results = {}
    network_semaphore = asyncio.Semaphore(2)
    scan_tasks = [scan_single_ip_async(ip, network_semaphore) for ip in reachable_ips]
    scan_results = await asyncio.gather(*scan_tasks)
    
    for result in scan_results:
        if result and (result["open_ports"] or result["mac_address"]):
            results[result["host"]] = result
    
    return results
