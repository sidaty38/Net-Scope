"""
Moteur principal du framework NetScope 
Orchestration des scans et gestion des résultats
"""
import time
import socket
from typing import Dict, List, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os

# Ajout du chemin parent pour les imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.plugin_manager import PluginManager
from core.utils import parse_ip_range, parse_port_range, format_timestamp, calculate_scan_duration, validate_ip
from config.settings import SCAN_CONFIG

class ScanEngine:
    """Moteur de scan principal - VERSION AMÉLIORÉE"""
    
    def __init__(self):
        self.plugin_manager = PluginManager()
        self.scan_results = []
        self.scan_history = []
        self.current_scan_id = None
        
    def resolve_domain(self, target: str) -> tuple:
        """
        NOUVEAU : Résout un nom de domaine en IP
        
        Args:
            target: Nom de domaine ou IP
            
        Returns:
            (ip, hostname, is_domain)
        """
        # Vérifier si c'est déjà une IP
        if validate_ip(target):
            return (target, target, False)
        
        # Essayer de résoudre le nom de domaine
        try:
            print(f"[*] Résolution DNS de {target}...")
            ip = socket.gethostbyname(target)
            print(f"    ✓ {target} → {ip}")
            return (ip, target, True)
        except socket.gaierror:
            raise ValueError(f"Impossible de résoudre le nom de domaine: {target}")
        except Exception as e:
            raise ValueError(f"Erreur lors de la résolution DNS: {e}")
    
    def create_scan_session(self, target: str, scan_type: str) -> str:
        """Crée une nouvelle session de scan"""
        scan_id = f"scan_{int(time.time())}"
        self.current_scan_id = scan_id
        
        session = {
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type,
            'start_time': time.time(),
            'timestamp': format_timestamp(),
            'status': 'running',
            'results': []
        }
        
        self.scan_history.append(session)
        return scan_id
    
    def update_scan_session(self, scan_id: str, results: Dict[str, Any]):
        """Met à jour une session de scan"""
        for session in self.scan_history:
            if session['scan_id'] == scan_id:
                session['results'].append(results)
                session['status'] = 'completed'
                session['end_time'] = time.time()
                session['duration'] = calculate_scan_duration(
                    session['start_time'],
                    session['end_time']
                )
    
    def quick_scan(self, target: str, ports: list = None) -> dict:
        """
        SCAN RAPIDE ⚡
        - Ports: 17 ports communs
        - Techniques: TCP SYN + Banner Grabbing
        - Durée: ~5-10 secondes
        - Usage: Découverte rapide
        
        Args:
            target: IP ou nom de domaine
            ports: Liste de ports (optionnel, sinon ports communs)
            
        Returns:
            Résultats du scan
        """
        from config.settings import COMMON_PORTS
        
        scan_ports = ports if ports else COMMON_PORTS
        
        print("\n" + "="*60)
        print("⚡ QUICK SCAN - Découverte Rapide")
        print("="*60)
        print(f"Ports scannés: {len(scan_ports)} ports communs")
        print(f"Techniques: TCP SYN + Banner Grabbing")
        print("="*60 + "\n")
        
        # Quick scan = TCP + Banner grabbing
        return self.scan_target(
            target,
            scan_types=['TCP_SYN', 'BANNER_GRABBER'],
            ports=scan_ports
        )
    
    def deep_scan(self, target: str, ports: list = None) -> dict:
        """
        SCAN APPROFONDI 🔍
        - Ports: 17 ports communs
        - Techniques: TCP SYN + UDP + Banner Grabbing AVANCÉ + ML Detection + Analyse sécurité
        - Durée: ~30-60 secondes
        - Usage: Analyse complète avec détection vulnérabilités
        
        Args:
            target: IP ou nom de domaine
            ports: Liste de ports (optionnel, sinon ports communs)
            
        Returns:
            Résultats du scan complet
        """
        from config.settings import COMMON_PORTS
        
        scan_ports = ports if ports else COMMON_PORTS
        
        print("\n" + "="*60)
        print("🔍 DEEP SCAN - Analyse Complète")
        print("="*60)
        print(f"Ports scannés: {len(scan_ports)} ports communs")
        print(f"Techniques: TCP + UDP + Banner Advanced + ML + Sécurité")
        print("="*60 + "\n")
        
        # Deep scan = TOUS les plugins (4 plugins)
        return self.scan_target(
            target,
            scan_types=['TCP_SYN', 'UDP_SCANNER', 'BANNER_GRABBER', 'SERVICE_DETECTOR'],
            ports=scan_ports
        )
    
    def custom_scan(self, target: str, scan_types: list, ports: list = None) -> dict:
        """
        SCAN PERSONNALISÉ 🎨
        - Ports: VOUS choisissez
        - Techniques: VOUS choisissez
        - Durée: Variable
        - Usage: Scan sur-mesure pour vos besoins
        
        Args:
            target: IP ou nom de domaine
            scan_types: Liste des types de scan à effectuer
            ports: Liste spécifique de ports
            
        Returns:
            Résultats du scan personnalisé
        """
        from config.settings import COMMON_PORTS
        
        scan_ports = ports if ports else COMMON_PORTS
        
        print("\n" + "="*60)
        print("🎨 CUSTOM SCAN - Personnalisé")
        print("="*60)
        print(f"Ports scannés: {len(scan_ports)} ports spécifiés")
        print(f"Techniques: {', '.join(scan_types)}")
        print("="*60 + "\n")
        
        return self.scan_target(target, scan_types, scan_ports)
    
    def scan_target(self, target: str, scan_types: list, ports: list) -> dict:
        """
        Scan d'une cible avec support DNS
        
        Args:
            target: IP ou nom de domaine
            scan_types: Liste des types de scan
            ports: Liste des ports
            
        Returns:
            Résultats du scan
        """
        # NOUVEAU : Résolution DNS si nécessaire
        try:
            ip, hostname, is_domain = self.resolve_domain(target)
        except ValueError as e:
            return {
                'error': str(e),
                'target': target
            }
        
        # Création de la session
        scan_id = self.create_scan_session(ip, ', '.join(scan_types))
        start_time = time.time()
        
        print(f"\n[*] Scan de {hostname} ({ip})")
        if is_domain:
            print(f"    🌐 Nom de domaine résolu: {hostname} → {ip}")
        print(f"[*] Scan ID: {scan_id}")
        print(f"[*] Types: {', '.join(scan_types)}")
        print(f"[*] Ports: {len(ports)} ports\n")
        
        # Parse la range d'IPs si nécessaire
        ip_list = parse_ip_range(ip)
        
        results = {
            'scan_id': scan_id,
            'target': target,
            'target_ip': ip,
            'hostname': hostname,
            'is_domain': is_domain,
            'scan_types': ', '.join(scan_types),
            'timestamp': format_timestamp(),
            'results': []
        }
        
        # Scanner chaque IP
        for target_ip in ip_list:
            host_result = {
                'ip': target_ip,
                'hostname': hostname if is_domain else target_ip,
                'scans': {}
            }
            
            # Exécuter chaque type de scan
            for scan_type in scan_types:
                try:
                    plugin = self.plugin_manager.get_plugin(scan_type)
                    
                    if not plugin:
                        print(f"[!] Plugin {scan_type} non trouvé")
                        continue
                    
                    print(f"\n[+] Exécution de {scan_type} sur {target_ip}")
                    
                    # Paramètres du scan
                    scan_params = {
                        'timeout': SCAN_CONFIG['timeout'],
                        'max_threads': SCAN_CONFIG['max_threads']
                    }
                    
                    # Si c'est un scanner de ports, passer la liste de ports
                    if scan_type in ['TCP_SYN', 'UDP_SCANNER']:
                        scan_params['ports'] = ports
                        scan_result = plugin.run(target_ip, **scan_params)
                    
                    # Si c'est banner grabbing, passer les ports ouverts du scan TCP
                    elif scan_type == 'BANNER_GRABBER':
                        # Récupérer les ports ouverts du scan TCP
                        tcp_results = host_result['scans'].get('TCP_SYN', {})
                        open_ports = tcp_results.get('open_ports', [])
                        
                        if open_ports:
                            scan_params['ports'] = open_ports
                            scan_result = plugin.run(target_ip, **scan_params)
                        else:
                            print(f"    ⚠️  Aucun port ouvert trouvé, skip banner grabbing")
                            continue
                    
                    # Si c'est service detector, utiliser les résultats précédents
                    elif scan_type == 'SERVICE_DETECTOR':
                        # Récupérer les infos des scans précédents
                        tcp_results = host_result['scans'].get('TCP_SYN', {})
                        banner_results = host_result['scans'].get('BANNER_GRABBER', {})
                        
                        scan_params['tcp_results'] = tcp_results
                        scan_params['banner_results'] = banner_results
                        scan_result = plugin.run(target_ip, **scan_params)
                    
                    else:
                        scan_result = plugin.run(target_ip, **scan_params)
                    
                    host_result['scans'][scan_type] = scan_result
                    
                except Exception as e:
                    print(f"[!] Erreur lors du scan {scan_type}: {e}")
                    host_result['scans'][scan_type] = {'error': str(e)}
            
            results['results'].append(host_result)
        
        # Calculer la durée
        end_time = time.time()
        results['duration'] = calculate_scan_duration(start_time, end_time)
        
        # Mettre à jour la session
        self.update_scan_session(scan_id, results)
        
        return results
    
    def get_scan_history(self, limit: int = 10) -> list:
        """Retourne l'historique des scans"""
        return self.scan_history[-limit:]
    
    def get_scan_by_id(self, scan_id: str) -> Optional[dict]:
        """Récupère un scan spécifique"""
        for scan in self.scan_history:
            if scan['scan_id'] == scan_id:
                return scan
        return None
    
    def compare_scans(self, scan_id1: str, scan_id2: str) -> dict:
        """Compare deux scans"""
        scan1 = self.get_scan_by_id(scan_id1)
        scan2 = self.get_scan_by_id(scan_id2)
        
        if not scan1 or not scan2:
            return {'error': 'Un ou plusieurs scans non trouvés'}
        
        comparison = {
            'scan1': scan_id1,
            'scan2': scan_id2,
            'differences': {
                'new_hosts': [],
                'removed_hosts': [],
                'new_ports': [],
                'closed_ports': [],
                'changed_services': []
            }
        }
        
        # Comparaison basique des hôtes
        hosts1 = set([r['ip'] for r in scan1.get('results', [])])
        hosts2 = set([r['ip'] for r in scan2.get('results', [])])
        
        comparison['differences']['new_hosts'] = list(hosts2 - hosts1)
        comparison['differences']['removed_hosts'] = list(hosts1 - hosts2)
        
        return comparison
    
    def get_statistics(self) -> dict:
        """Retourne des statistiques globales"""
        total_scans = len(self.scan_history)
        total_hosts = set()
        total_ports = 0
        
        for scan in self.scan_history:
            for result in scan.get('results', []):
                total_hosts.add(result.get('ip'))
                
                # Compter les ports ouverts
                for scan_type, scan_result in result.get('scans', {}).items():
                    if scan_type == 'TCP_SYN':
                        total_ports += len(scan_result.get('open_ports', []))
        
        return {
            'total_scans': total_scans,
            'unique_hosts': len(total_hosts),
            'total_open_ports': total_ports,
            'last_scan': self.scan_history[-1] if self.scan_history else None
        }
