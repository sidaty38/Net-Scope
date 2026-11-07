"""
Plugin de scan TCP SYN pour NetScope
Implémentation d'un scanner TCP SYN (stealth scan)
"""
import socket
import struct
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.plugin_manager import PluginBase
from core.utils import validate_ip, parse_port_range, is_port_open_quick
from config.settings import SCAN_CONFIG, COMMON_PORTS

class TCPSYNScanner(PluginBase):
    """Scanner TCP SYN (half-open scan)"""
    
    def __init__(self):
        super().__init__()
        self.name = "TCP_SYN"
        self.description = "Scanner TCP SYN pour détection de ports ouverts"
        self.version = "1.0"
        self.requires_root = False  # Mode connect pour éviter besoin root
    
    def get_info(self) -> Dict[str, str]:
        """Retourne les informations du plugin"""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'requires_root': str(self.requires_root)
        }
    
    def validate_input(self, target: str) -> bool:
        """Valide l'IP cible"""
        return validate_ip(target)
    
    def scan_port(self, ip: str, port: int, timeout: float) -> Dict[str, Any]:
        """
        Scan un port spécifique
        
        Args:
            ip: IP cible
            port: Port à scanner
            timeout: Timeout du scan
            
        Returns:
            Résultat du scan
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': self._guess_service(port)
        }
        
        try:
            # TCP Connect scan (pas besoin de root)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            connection_result = sock.connect_ex((ip, port))
            sock.close()
            
            if connection_result == 0:
                result['state'] = 'open'
            elif connection_result == 111:  # Connection refused
                result['state'] = 'closed'
            else:
                result['state'] = 'filtered'
                
        except socket.timeout:
            result['state'] = 'filtered'
        except socket.error as e:
            result['state'] = 'error'
            result['error'] = str(e)
        except Exception as e:
            result['state'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def _guess_service(self, port: int) -> str:
        """Devine le service associé à un port"""
        common_services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return common_services.get(port, 'unknown')
    
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute le scan TCP SYN
        
        Args:
            target: IP cible
            **kwargs: ports (liste de ports), timeout, threads
            
        Returns:
            Résultats du scan
        """
        # Récupération des paramètres
        ports = kwargs.get('ports', COMMON_PORTS)
        timeout = kwargs.get('timeout', SCAN_CONFIG['timeout'])
        max_threads = kwargs.get('threads', SCAN_CONFIG['max_threads'])
        
        # Si ports est une chaîne, la parser
        if isinstance(ports, str):
            ports = parse_port_range(ports)
        
        if not ports:
            ports = COMMON_PORTS
        
        results = {
            'ip': target,
            'total_ports': len(ports),
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'scan_type': 'TCP SYN',
            'timestamp': ''
        }
        
        # Scan multithread
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target, port, timeout): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                try:
                    port_result = future.result()
                    
                    if port_result['state'] == 'open':
                        results['open_ports'].append(port_result)
                    elif port_result['state'] == 'closed':
                        results['closed_ports'].append(port_result['port'])
                    elif port_result['state'] == 'filtered':
                        results['filtered_ports'].append(port_result['port'])
                        
                except Exception as e:
                    print(f"[!] Erreur lors du scan du port: {e}")
        
        # Tri des résultats
        results['open_ports'].sort(key=lambda x: x['port'])
        results['summary'] = f"{len(results['open_ports'])} ports ouverts sur {len(ports)} scannés"
        
        return results
