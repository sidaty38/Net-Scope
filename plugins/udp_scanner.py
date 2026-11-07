"""
Plugin de scan UDP pour NetScope
Détection de ports UDP ouverts
"""
import socket
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.plugin_manager import PluginBase
from core.utils import validate_ip
from config.settings import SCAN_CONFIG

class UDPScanner(PluginBase):
    """Scanner UDP"""
    
    def __init__(self):
        super().__init__()
        self.name = "UDP_SCANNER"
        self.description = "Scanner UDP pour détection de services UDP"
        self.version = "1.0"
        
        # Ports UDP communs
        self.common_udp_ports = [
            53,    # DNS
            67,    # DHCP Server
            68,    # DHCP Client
            69,    # TFTP
            123,   # NTP
            161,   # SNMP
            162,   # SNMP Trap
            500,   # IKE
            514,   # Syslog
            1900,  # SSDP
            4500,  # IPSec NAT
        ]
    
    def get_info(self) -> Dict[str, str]:
        """Retourne les informations du plugin"""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def validate_input(self, target: str) -> bool:
        """Valide l'IP cible"""
        return validate_ip(target)
    
    def scan_udp_port(self, ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
        """
        Scan un port UDP
        
        Args:
            ip: IP cible
            port: Port UDP
            timeout: Timeout
            
        Returns:
            Résultat du scan
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': self._guess_udp_service(port)
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Envoi d'un paquet vide
            sock.sendto(b'', (ip, port))
            
            try:
                # Tentative de réception
                data, addr = sock.recvfrom(1024)
                result['state'] = 'open'
                result['response'] = len(data)
            except socket.timeout:
                # Pas de réponse = probablement ouvert ou filtré
                result['state'] = 'open|filtered'
            except socket.error as e:
                # ICMP Port Unreachable = fermé
                if 'Connection refused' in str(e):
                    result['state'] = 'closed'
                else:
                    result['state'] = 'open|filtered'
            
            sock.close()
            
        except Exception as e:
            result['state'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def _guess_udp_service(self, port: int) -> str:
        """Devine le service UDP associé au port"""
        udp_services = {
            53: 'DNS',
            67: 'DHCP-Server',
            68: 'DHCP-Client',
            69: 'TFTP',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            500: 'IKE',
            514: 'Syslog',
            1900: 'SSDP',
            4500: 'IPSec-NAT'
        }
        return udp_services.get(port, 'unknown')
    
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute le scan UDP
        
        Args:
            target: IP cible
            **kwargs: ports, timeout, threads
            
        Returns:
            Résultats du scan
        """
        ports = kwargs.get('ports', self.common_udp_ports)
        timeout = kwargs.get('timeout', 2.0)
        max_threads = kwargs.get('threads', 10)  # Moins de threads pour UDP
        
        if isinstance(ports, str):
            from core.utils import parse_port_range
            ports = parse_port_range(ports)
        
        if not ports:
            ports = self.common_udp_ports
        
        results = {
            'ip': target,
            'total_ports': len(ports),
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_type': 'UDP',
            'note': 'UDP scan peut être moins précis que TCP'
        }
        
        # Scan multithread
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_udp_port, target, port, timeout): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                try:
                    port_result = future.result()
                    
                    if 'open' in port_result['state']:
                        results['open_ports'].append(port_result)
                    elif port_result['state'] == 'closed':
                        results['closed_ports'].append(port_result['port'])
                    else:
                        results['filtered_ports'].append(port_result['port'])
                        
                except Exception as e:
                    print(f"[!] Erreur scan UDP: {e}")
        
        results['open_ports'].sort(key=lambda x: x['port'])
        results['summary'] = f"{len(results['open_ports'])} ports UDP ouverts/filtrés sur {len(ports)} scannés"
        
        return results
