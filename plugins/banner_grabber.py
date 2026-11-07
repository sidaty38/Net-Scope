"""
Plugin de Banner Grabbing ULTRA-AVANCÉ pour NetScope
Techniques avancées inspirées de Nmap pour obtenir plus d'informations
"""
import socket
import ssl
import sys
import os
import time
from typing import Dict, Any, Optional, List

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.plugin_manager import PluginBase
from core.utils import validate_ip
from config.settings import SCAN_CONFIG

class AdvancedBannerGrabber(PluginBase):
    """Banner Grabber ULTRA-AVANCÉ avec techniques multiples"""
    
    def __init__(self):
        super().__init__()
        self.name = "BANNER_GRABBER"
        self.description = "Banner grabbing avancé avec probes multiples"
        self.version = "2.0"
        
        # TECHNIQUE 1 : PROBES MULTIPLES (comme Nmap)
        self.http_probes = [
            # Probe 1 : Requête normale
            b'GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetScope/2.0\r\nConnection: close\r\n\r\n',
            
            # Probe 2 : Requête OPTIONS (révèle souvent plus d'infos)
            b'OPTIONS / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetScope/2.0\r\n\r\n',
            
            # Probe 3 : Requête HEAD (léger, rapide)
            b'HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetScope/2.0\r\n\r\n',
            
            # Probe 4 : Requête invalide (provoque erreur = infos)
            b'GET /\\x00 HTTP/1.0\r\n\r\n',
            
            # Probe 5 : Ancienne version HTTP
            b'GET / HTTP/1.0\r\n\r\n',
        ]
        
        # TECHNIQUE 2 : PROBES POUR FICHIERS SPÉCIAUX
        self.special_paths = [
            '/robots.txt',      # Révèle souvent des infos
            '/server-status',   # Apache status
            '/.well-known/',    # Configuration moderne
            '/phpinfo.php',     # Si PHP
            '/info.php',
        ]
    
    def get_info(self) -> Dict[str, str]:
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'techniques': 'Multi-probe, Error analysis, SSL inspection'
        }
    
    def validate_input(self, target: str) -> bool:
        return validate_ip(target)
    
    def grab_banner_multiple_probes(self, ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """
        TECHNIQUE AVANCÉE : Essayer plusieurs probes
        
        Args:
            ip: IP cible
            port: Port
            timeout: Timeout
            
        Returns:
            Dictionnaire avec toutes les infos collectées
        """
        collected_info = {
            'banners': [],
            'headers': {},
            'server': None,
            'powered_by': None,
            'error_messages': [],
            'ssl_info': {}
        }
        
        # Si c'est HTTPS, récupérer infos SSL d'abord
        if port in [443, 8443]:
            ssl_info = self.get_ssl_info(ip, port, timeout)
            if ssl_info:
                collected_info['ssl_info'] = ssl_info
        
        # HTTP/HTTPS : Essayer plusieurs probes
        if port in [80, 443, 8000, 8080, 8443]:
            for i, probe_template in enumerate(self.http_probes):
                try:
                    # Remplacer {host} par l'IP
                    probe = probe_template.replace(b'{host}', ip.encode())
                    
                    banner = self._send_probe(ip, port, probe, timeout, use_ssl=(port in [443, 8443]))
                    
                    if banner:
                        collected_info['banners'].append({
                            'probe': f'HTTP-{i+1}',
                            'content': banner
                        })
                        
                        # Extraire les headers
                        headers = self._extract_http_headers(banner)
                        collected_info['headers'].update(headers)
                        
                        # Si on a trouvé Server header, on peut arrêter
                        if 'server' in headers and i < 2:
                            # Mais essayer quand même un probe d'erreur
                            continue
                        
                except Exception as e:
                    pass
                
                time.sleep(0.1)  # Petit délai entre probes
        
        else:
            # Pour les autres services, probe simple
            banner = self._send_probe(ip, port, b'', timeout)
            if banner:
                collected_info['banners'].append({
                    'probe': 'default',
                    'content': banner
                })
        
        return collected_info
    
    def _send_probe(self, ip: str, port: int, probe: bytes, timeout: float, use_ssl: bool = False) -> Optional[str]:
        """
        Envoie un probe et récupère la réponse
        
        Args:
            ip: IP cible
            port: Port
            probe: Données à envoyer
            timeout: Timeout
            use_ssl: Utiliser SSL/TLS
            
        Returns:
            Bannière ou None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # SSL si nécessaire
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
            
            # Envoi du probe
            if probe:
                sock.send(probe)
            
            # Réception
            banner = b''
            sock.settimeout(1.0)  # Timeout court pour recv
            
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    banner += data
                    if len(banner) > 16384:  # Limite 16KB
                        break
            except socket.timeout:
                pass  # Normal
            
            sock.close()
            
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
            
        except Exception as e:
            pass
        
        return None
    
    def _extract_http_headers(self, response: str) -> Dict[str, str]:
        """
        TECHNIQUE : Extraire TOUS les headers HTTP (pas juste Server)
        
        Args:
            response: Réponse HTTP
            
        Returns:
            Dictionnaire de headers
        """
        headers = {}
        
        lines = response.split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                # Headers révélateurs
                if key in ['server', 'x-powered-by', 'x-aspnet-version', 
                          'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache',
                          'x-varnish', 'via', 'x-backend-server']:
                    headers[key] = value
        
        return headers
    
    def get_ssl_info(self, ip: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
        """
        TECHNIQUE : Récupérer infos du certificat SSL
        (Révèle souvent des infos même si le serveur masque sa bannière)
        
        Args:
            ip: IP cible
            port: Port HTTPS
            timeout: Timeout
            
        Returns:
            Informations SSL
        """
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extraire infos du certificat
                    if cert:
                        # Sujet du certificat
                        subject = dict(x[0] for x in cert.get('subject', ()))
                        ssl_info['common_name'] = subject.get('commonName', '')
                        ssl_info['organization'] = subject.get('organizationName', '')
                        
                        # Émetteur
                        issuer = dict(x[0] for x in cert.get('issuer', ()))
                        ssl_info['issuer'] = issuer.get('commonName', '')
                        
                        # Dates
                        ssl_info['not_before'] = cert.get('notBefore', '')
                        ssl_info['not_after'] = cert.get('notAfter', '')
                    
                    # Version TLS
                    ssl_info['tls_version'] = ssock.version()
                    
        except Exception as e:
            pass
        
        return ssl_info
    
    def fingerprint_by_behavior(self, ip: str, port: int) -> Dict[str, str]:
        """
        TECHNIQUE : Fingerprinting par comportement
        (Même sans bannière, on peut deviner le serveur par son comportement)
        
        Args:
            ip: IP cible
            port: Port
            
        Returns:
            Informations devinées
        """
        fingerprint = {
            'probable_server': 'unknown',
            'confidence': 0.0,
            'indicators': []
        }
        
        # Test 1 : Réponse à requête invalide
        try:
            response = self._send_probe(ip, port, b'INVALID REQUEST\r\n\r\n', 2.0)
            
            if response:
                response_lower = response.lower()
                
                # Apache patterns
                if 'apache' in response_lower or '400 bad request' in response_lower:
                    fingerprint['probable_server'] = 'Apache'
                    fingerprint['confidence'] = 0.7
                    fingerprint['indicators'].append('Apache error pattern')
                
                # Nginx patterns
                elif 'nginx' in response_lower or '<hr><center>nginx</center>' in response_lower:
                    fingerprint['probable_server'] = 'nginx'
                    fingerprint['confidence'] = 0.8
                    fingerprint['indicators'].append('nginx error pattern')
                
                # IIS patterns
                elif 'microsoft' in response_lower or 'iis' in response_lower:
                    fingerprint['probable_server'] = 'IIS'
                    fingerprint['confidence'] = 0.7
                    fingerprint['indicators'].append('IIS error pattern')
        
        except Exception as e:
            pass
        
        # Test 2 : Timing analysis (avancé)
        # Certains serveurs ont des patterns de timing caractéristiques
        
        return fingerprint
    
    def analyze_banner_advanced(self, collected_info: Dict[str, Any], port: int) -> Dict[str, str]:
        """
        Analyse avancée de toutes les infos collectées
        
        Args:
            collected_info: Toutes les infos collectées
            port: Port
            
        Returns:
            Informations synthétisées
        """
        info = {
            'service': 'unknown',
            'version': 'unknown',
            'details': '',
            'confidence': 'low',
            'collection_method': []
        }
        
        # Priorité 1 : Headers HTTP directs
        headers = collected_info.get('headers', {})
        
        if 'server' in headers:
            info['version'] = headers['server']
            info['service'] = headers['server'].split('/')[0]
            info['confidence'] = 'high'
            info['collection_method'].append('Server header')
        
        if 'x-powered-by' in headers:
            info['details'] = f"Powered by: {headers['x-powered-by']}"
            info['collection_method'].append('X-Powered-By header')
        
        # Priorité 2 : Bannières collectées
        banners = collected_info.get('banners', [])
        
        for banner_data in banners:
            banner = banner_data.get('content', '')
            
            if 'ssh' in banner.lower():
                info['service'] = 'SSH'
                lines = banner.split('\n')
                if lines:
                    info['version'] = lines[0][:100]
                info['confidence'] = 'high'
                info['collection_method'].append('SSH banner')
                break
            
            elif 'ftp' in banner.lower():
                info['service'] = 'FTP'
                lines = banner.split('\n')
                if lines:
                    info['version'] = lines[0][:100]
                info['confidence'] = 'high'
                info['collection_method'].append('FTP banner')
                break
        
        # Priorité 3 : Infos SSL
        ssl_info = collected_info.get('ssl_info', {})
        if ssl_info:
            if info['details']:
                info['details'] += ' | '
            info['details'] += f"SSL: {ssl_info.get('common_name', 'unknown')}"
            info['collection_method'].append('SSL certificate')
        
        # Priorité 4 : Fingerprinting
        if info['service'] == 'unknown' and port in [80, 8080, 443]:
            # Essayer de deviner par les patterns d'erreur
            for banner_data in banners:
                banner = banner_data.get('content', '').lower()
                
                if 'apache' in banner:
                    info['service'] = 'Apache'
                    info['confidence'] = 'medium'
                    info['collection_method'].append('Error pattern matching')
                elif 'nginx' in banner:
                    info['service'] = 'nginx'
                    info['confidence'] = 'medium'
                    info['collection_method'].append('Error pattern matching')
        
        return info
    
    def grab_banner(self, ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
        """
        Version améliorée du grab_banner (pour compatibilité)
        """
        collected = self.grab_banner_multiple_probes(ip, port, timeout)
        
        # Retourner la meilleure bannière
        banners = collected.get('banners', [])
        if banners:
            return banners[0].get('content', '')
        
        return None
    
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute le banner grabbing AVANCÉ
        
        Args:
            target: IP cible
            **kwargs: ports (liste de ports ouverts)
            
        Returns:
            Résultats du banner grabbing
        """
        open_ports = kwargs.get('ports', [])
        timeout = kwargs.get('timeout', 3.0)
        
        if open_ports and isinstance(open_ports[0], dict):
            open_ports = [p['port'] for p in open_ports]
        
        results = {
            'ip': target,
            'services': [],
            'vulnerabilities': [],
            'scan_type': 'Advanced Banner Grabbing',
            'techniques_used': [
                'Multiple HTTP probes',
                'SSL certificate inspection',
                'HTTP headers analysis',
                'Error-based fingerprinting'
            ]
        }
        
        for port in open_ports:
            print(f"[*] Banner grabbing avancé sur {target}:{port}...")
            
            # Collecte multi-techniques
            collected_info = self.grab_banner_multiple_probes(target, port, timeout)
            
            # Analyse avancée
            service_info = self.analyze_banner_advanced(collected_info, port)
            service_info['port'] = port
            
            # Ajout des infos brutes
            if collected_info.get('banners'):
                best_banner = collected_info['banners'][0]['content']
                service_info['banner'] = best_banner[:500]
                service_info['banner_length'] = len(best_banner)
            else:
                service_info['banner'] = 'No banner received'
            
            # Ajout des headers HTTP si présents
            if collected_info.get('headers'):
                service_info['http_headers'] = collected_info['headers']
            
            # Ajout des infos SSL si présentes
            if collected_info.get('ssl_info'):
                service_info['ssl_info'] = collected_info['ssl_info']
            
            results['services'].append(service_info)
            
            # Affichage de ce qui a été trouvé
            if service_info.get('version') != 'unknown':
                print(f"    ✓ Version: {service_info['version']}")
            if service_info.get('http_headers'):
                print(f"    ✓ Headers: {len(service_info['http_headers'])} trouvés")
            if service_info.get('ssl_info'):
                print(f"    ✓ SSL: {service_info['ssl_info'].get('common_name', 'N/A')}")
            
            print(f"    📊 Confiance: {service_info.get('confidence', 'unknown')}")
            print(f"    🔍 Méthode: {', '.join(service_info.get('collection_method', ['none']))}")
        
        results['summary'] = f"{len([s for s in results['services'] if s.get('version') != 'unknown'])} services identifiés avec {len(results['techniques_used'])} techniques"
        
        return results
