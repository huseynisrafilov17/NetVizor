import aioping
import asyncio
import socket
import ipaddress
from scapy.all import srp, Ether, ARP, conf, sr1, IP, TCP


WELL_KNOWN_PORTS = list(range(1, 1025)) + [
    1701, 1723, 3306, 3389, 5900, 8080, 8443, 9000,
    10000, 2049, 3128, 3690, 5000, 5432, 6379, 9200,
    9300, 11211, 27017, 27018, 27019, 50000, 50001
]

def is_valid_ipv4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True

def is_valid_subnet(subnet):
    try:
        ip, mask = subnet.split('/')
        mask = int(mask)
        if is_valid_ipv4(ip):
            return 0 <= mask <= 32
        else:
            return False
    except ValueError:
        return False

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
        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(pkt, timeout=2, retry=2)
        
        for sent, received in answered:
            return received.hwsrc
    except Exception as e:
        print(f"Error retrieving MAC address for {ip}: {e}")
        return None

def detect_os(target_ip):
    try:
        # Send a SYN packet to the target
        pkt = IP(dst=target_ip) / TCP(dport=80, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)

        if response and response.haslayer(TCP):
            window_size = response.getlayer(TCP).window
            if window_size == 65535:
                return "Windows"
            elif window_size == 5840 or window_size == 5720:
                return "Linux"
            elif window_size == 8760:
                return "FreeBSD"
            else:
                return "Unknown OS"
        else:
            return "No Response"
    except Exception as e:
        return f"Error: {e}"

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
    if is_valid_ipv4(ip) and ip.split(".")[3] != "0":
        try:
            async with semaphore:
                open_ports = await scan_ports_async(ip, WELL_KNOWN_PORTS)
                hostname = get_hostname(ip)
                mac_address = get_mac_address(ip)
                os = detect_os(ip)
                return {
                    "hostname": hostname,
                    "host": ip,
                    "mac_address": mac_address.upper(),
                    "os": os,
                    "group": "host",
                    "open_ports": open_ports
                }
        except:
            return None
    else:
        return {"error": "Please enter a valid IP address."}

async def scan_network_async(subnet):
    if is_valid_subnet(subnet):
        reachable_ips = []
        tasks = [ping_host(str(ip)) for ip in ipaddress.IPv4Network(subnet, strict=False)]
        ping_results = await asyncio.gather(*tasks)
        reachable_ips = [ip for ip in ping_results if ip is not None]
    
        results = {}
        network_semaphore = asyncio.Semaphore(1)
        scan_tasks = [scan_single_ip_async(ip, network_semaphore) for ip in reachable_ips]
        scan_results = await asyncio.gather(*scan_tasks)
        ID = 1
    
        for result in scan_results:
            if result and (result["open_ports"] or result["mac_address"]):
                results[f"{ID}"] = result
                ID += 1
    
        return results
    else:
        return {"error": "Please enter a valid IP address."}