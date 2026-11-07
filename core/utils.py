"""
Utilitaires pour le framework NetScope
"""
import ipaddress
import socket
import struct
import time
from typing import List, Tuple
from datetime import datetime

def validate_ip(ip: str) -> bool:
    """Valide une adresse IP"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: int) -> bool:
    """Valide un numéro de port"""
    return 1 <= port <= 65535

def parse_ip_range(ip_range: str) -> List[str]:
    """Parse un range d'IPs (ex: 192.168.1.0/24)"""
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        # Si c'est une seule IP
        if validate_ip(ip_range):
            return [ip_range]
        return []

def parse_port_range(port_range: str) -> List[int]:
    """Parse un range de ports (ex: 80,443,8000-8100)"""
    ports = []
    try:
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return [p for p in ports if validate_port(p)]
    except ValueError:
        return []

def calculate_checksum(data: bytes) -> int:
    """Calcule le checksum pour les paquets TCP/IP"""
    if len(data) % 2 == 1:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff
    return checksum

def create_tcp_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Crée un paquet TCP SYN brut"""
    # IP Header
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 40  # 20 IP + 20 TCP
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
                           ip_ihl_ver, ip_tos, ip_tot_len,
                           ip_id, ip_frag_off, ip_ttl,
                           ip_proto, ip_check,
                           ip_saddr, ip_daddr)
    
    # TCP Header
    tcp_source = src_port
    tcp_dest = dst_port
    tcp_seq = 0
    tcp_ack_seq = 0
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    tcp_flags = 0x02  # SYN flag
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_header = struct.pack('!HHLLBBHHH',
                            tcp_source, tcp_dest, tcp_seq,
                            tcp_ack_seq, tcp_offset_res,
                            tcp_flags, tcp_window, tcp_check,
                            tcp_urg_ptr)
    
    # Pseudo header for checksum
    source_address = socket.inet_aton(src_ip)
    dest_address = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    psh = struct.pack('!4s4sBBH',
                     source_address, dest_address,
                     placeholder, protocol, tcp_length)
    psh = psh + tcp_header
    
    tcp_check = calculate_checksum(psh)
    
    tcp_header = struct.pack('!HHLLBBH',
                            tcp_source, tcp_dest, tcp_seq,
                            tcp_ack_seq, tcp_offset_res,
                            tcp_flags, tcp_window) + \
                struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    
    return ip_header + tcp_header

def format_timestamp() -> str:
    """Retourne un timestamp formaté"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def calculate_scan_duration(start_time: float, end_time: float) -> str:
    """
    Calcule la durée du scan
    
    Args:
        start_time: Timestamp de début
        end_time: Timestamp de fin
        
    Returns:
        Durée formatée (ex: "1m 23.45s")
    """
    duration = end_time - start_time
    
    if duration < 60:
        return f"{duration:.2f}s"
    else:
        minutes = int(duration / 60)
        seconds = duration % 60
        return f"{minutes}m {seconds:.2f}s"

def get_local_ip() -> str:
    """Obtient l'IP locale de la machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def is_port_open_quick(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Test rapide si un port est ouvert (connect scan)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False
