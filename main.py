import socket
import time
import logging
from scapy.all import ARP, Ether, srp
from datetime import datetime
from manuf import manuf
from concurrent.futures import ThreadPoolExecutor
import netifaces as ni
from ipaddress import ip_network, IPv4Network
from logging.handlers import RotatingFileHandler

# Configure Logging
logger = logging.getLogger("NetworkScanner")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("scanner.log", maxBytes=50000, backupCount=3)
formatter = logging.Formatter('[%(asctime)s] %(message)s', "%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)

# Common ports with descriptions
PORTS = {
    21: ("FTP", "Old file transfer. Password cracking risk."),
    22: ("SSH", "Remote login. Weak passwords can be a risk."),
    23: ("Telnet", "Insecure, should be replaced by SSH."),
    25: ("SMTP", "Email server. Can be used to send spam if misconfigured."),
    53: ("DNS", "Name resolution. Vulnerable to poisoning and amplification."),
    69: ("TFTP", "Simple file transfer. No authentication."),
    80: ("HTTP", "Web server. Vulnerable to XSS, SQLi."),
    110: ("POP3", "Email retrieval. Often uses plaintext login."),
    111: ("RPCbind", "Remote procedure calls. Can be abused."),
    135: ("MS RPC", "Windows RPC. DCOM exploitation risk."),
    139: ("NetBIOS", "Windows file sharing. Information leakage."),
    143: ("IMAP", "Email protocol. Might use plaintext login."),
    161: ("SNMP", "Network monitoring. Default strings leak info."),
    389: ("LDAP", "Directory service. Used for enumeration."),
    443: ("HTTPS", "Secure HTTP. Can be misconfigured."),
    445: ("SMB", "Windows file sharing. EternalBlue target."),
    512: ("rexec", "Remote command exec. Weak auth."),
    513: ("rlogin", "Remote login. Trust-based, insecure."),
    514: ("rsh", "Remote shell. No encryption."),
    3306: ("MySQL", "SQL DB. Prone to injection."),
    3389: ("RDP", "Remote desktop. Brute-force target."),
    5900: ("VNC", "Remote desktop. Often lacks authentication."),
    8080: ("HTTP Alt", "Alternative HTTP port. Often proxy or admin panels."),
}

# MAC vendor lookup
vendor_lookup = manuf.MacParser()

# Cache for previously scanned hosts
host_cache = {}

def log(msg: str) -> None:
    logger.info(msg)
    print(msg)

def get_local_ip() -> str | None:
    try:
        iface = ni.gateways()['default'][ni.AF_INET][1]
        return ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
    except Exception as e:
        log(f"[!] Failed to get local IP: {e}")
        return None

def get_subnet() -> str | None:
    try:
        iface = ni.gateways()['default'][ni.AF_INET][1]
        info = ni.ifaddresses(iface)[ni.AF_INET][0]
        ip = info['addr']
        netmask = info['netmask']
        network = ip_network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except Exception as e:
        log(f"[!] Failed to calculate subnet: {e}")
        return None

def scan_network(network_range: str) -> list[dict]:
    log(f"[*] Scanning network: {network_range}")
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether/arp, timeout=2, verbose=False)[0]

    hosts = []
    for _, rcv in result:
        ip = rcv.psrc
        mac = rcv.hwsrc
        if ip and mac:
            hosts.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor_lookup.get_manuf(mac)
            })
    return hosts

def scan_single_port(ip: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False

def scan_ports_concurrent(host: dict) -> list[int]:
    open_ports = []
    ip = host["ip"]
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_single_port, ip, port): port for port in PORTS}
        for future in futures:
            try:
                if future.result():
                    open_ports.append(futures[future])
            except Exception:
                pass
    return open_ports

def run_network_scanner():
    local_ip = get_local_ip()
    if not local_ip:
        log("[!] Local IP not found.")
        return

    subnet = get_subnet()
    if not subnet:
        log("[!] Could not detect subnet.")
        return

    log(f"[*] Starting scan on subnet: {subnet}")
    
    while True:
        active_hosts = scan_network(subnet)
        current_time = time.time()

        # Track IPs currently active in this scan
        active_host_ids = set()

        for host in active_hosts:
            host_id = f"{host['ip']}_{host['mac']}"
            active_host_ids.add(host_id)

            # If new device, add to cache
            if host_id not in host_cache:
                host_cache[host_id] = {
                    "last_seen": current_time,
                    "open_ports": set()
                }
                log(f"[+] New device detected: {host['ip']} ({host['mac']}) [{host['vendor'] or 'Unknown'}]")
            else:
                # Update last seen time
                host_cache[host_id]["last_seen"] = current_time

            # Scan ports for device
            open_ports = scan_ports_concurrent(host)
            current_ports = set(open_ports)
            cached_ports = host_cache[host_id]["open_ports"]

            # Newly opened ports
            newly_open_ports = current_ports - cached_ports
            for port in newly_open_ports:
                service = PORTS[port][0]
                log(f"    [!] New open port detected on {host['ip']}: Port {port} - {service}")

            # Newly closed ports
            newly_closed_ports = cached_ports - current_ports
            for port in newly_closed_ports:
                service = PORTS[port][0]
                log(f"    [-] Port closed on {host['ip']}: Port {port} - {service}")

            # Update cache
            host_cache[host_id]["open_ports"] = current_ports

        # TODO: Optionally handle devices that disappeared (not in active_host_ids)
        # For example, remove from host_cache or mark offline

        time.sleep(5)


if __name__ == "__main__":
    try:
        run_network_scanner()
    except KeyboardInterrupt:
        log("[!] Scan stopped by user.")
