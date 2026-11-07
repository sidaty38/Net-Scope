#!/usr/bin/env python3
"""
NetScope - Mini-Framework de Scan Réseau Modulaire
Interface en ligne de commande principale
"""
import argparse
import sys
import os
import json
from datetime import datetime

# Ajout du chemin pour les imports
sys.path.insert(0, os.path.dirname(__file__))

from core.engine import ScanEngine
from core.utils import parse_ip_range, parse_port_range
from storage.database import DatabaseManager
from config.settings import COMMON_PORTS, VERSION

def print_banner():
    """Affiche la bannière du programme"""
    banner = f"""
    ╔════════════════════════════════════════════════════════════╗
    ║                                                            ║
    ║              🔍 NetScope v{VERSION}                         ║
    ║        Smart Network Intelligence Framework                ║
    ║                                                            ║
    ║  Mini-Framework de Scan Réseau Modulaire avec ML          ║
    ║                                                            ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_scan_results(results):
    """
    Affiche les résultats d'un scan de manière formatée
    
    Args:
        results: Résultats du scan
    """
    print("\n" + "=" * 60)
    print(f"📊 RÉSULTATS DU SCAN")
    print("=" * 60)
    print(f"🎯 Cible: {results.get('target')}")
    print(f"⏱️  Durée: {results.get('duration')}")
    print(f"🕐 Timestamp: {results.get('timestamp')}")
    print(f"🔍 Types de scan: {', '.join(results.get('scan_types', []))}")
    print("=" * 60)
    
    for result in results.get('results', []):
        ip = result.get('ip')
        print(f"\n🖥️  Hôte: {ip}")
        print("-" * 60)
        
        # Résultats TCP SYN
        tcp_scan = result.get('scans', {}).get('TCP_SYN', {})
        if tcp_scan:
            open_ports = tcp_scan.get('open_ports', [])
            print(f"\n✅ {tcp_scan.get('summary', 'Aucun résultat')}")
            
            if open_ports:
                print("\n   Port    État      Service")
                print("   " + "-" * 40)
                for port in open_ports:
                    print(f"   {port['port']:<7} {port['state']:<9} {port['service']}")
        
        # Résultats Banner Grabbing
        banner_scan = result.get('scans', {}).get('BANNER_GRABBER', {})
        if banner_scan:
            services = banner_scan.get('services', [])
            print(f"\n🏷️  {banner_scan.get('summary', '')}")
            
            if services:
                print("\n   Services détectés:")
                print("   " + "-" * 40)
                for service in services:
                    print(f"   Port {service['port']}: {service['service']}")
                    if service.get('version'):
                        print(f"      Version: {service['version']}")
                    if service.get('banner'):
                        banner = service['banner'][:80]
                        print(f"      Bannière: {banner}...")
            
            # Vulnérabilités
            vulns = banner_scan.get('vulnerabilities', [])
            if vulns:
                print(f"\n⚠️  {len(vulns)} vulnérabilité(s) potentielle(s) détectée(s):")
                for vuln in vulns:
                    print(f"   • {vuln}")
        
        # Résultats UDP
        udp_scan = result.get('scans', {}).get('UDP_SCANNER', {})
        if udp_scan:
            print(f"\n📡 {udp_scan.get('summary', '')}")
            open_ports = udp_scan.get('open_ports', [])
            if open_ports:
                print("\n   Ports UDP:")
                for port in open_ports:
                    print(f"   {port['port']}: {port['service']} ({port['state']})")
        
        # Résultats Service Detector (ML)
        ml_scan = result.get('scans', {}).get('SERVICE_DETECTOR', {})
        if ml_scan:
            print(f"\n🤖 {ml_scan.get('summary', '')}")
            
            security_score = ml_scan.get('security_score', {})
            if security_score:
                score = security_score['score']
                level = security_score['level']
                print(f"\n   Score de Sécurité: {score}/100 ({level})")
                
                issues = security_score.get('issues', [])
                if issues:
                    print(f"\n   Problèmes identifiés:")
                    for issue in issues:
                        print(f"   • {issue}")
            
            anomalies = ml_scan.get('anomalies', [])
            if anomalies:
                print(f"\n   Anomalies détectées:")
                for anomaly in anomalies:
                    print(f"   • {anomaly['description']} (Sévérité: {anomaly['severity']})")
        
        print("\n" + "-" * 60)
    
    print("\n✅ Scan terminé!\n")

def quick_scan(engine, target):
    """
    Effectue un scan rapide
    
    Args:
        engine: Instance du moteur de scan
        target: Cible du scan
    """
    print(f"\n[*] Lancement d'un scan rapide sur {target}...")
    results = engine.quick_scan(target)
    print_scan_results(results)
    return results

def deep_scan(engine, target):
    """
    Effectue un scan approfondi
    
    Args:
        engine: Instance du moteur de scan
        target: Cible du scan
    """
    print(f"\n[*] Lancement d'un scan approfondi sur {target}...")
    print("[!] Cela peut prendre plusieurs minutes...")
    results = engine.deep_scan(target)
    print_scan_results(results)
    return results

def custom_scan(engine, target, scan_types, ports):
    """
    Effectue un scan personnalisé
    
    Args:
        engine: Instance du moteur de scan
        target: Cible du scan
        scan_types: Types de scans à effectuer
        ports: Ports à scanner
    """
    print(f"\n[*] Lancement d'un scan personnalisé sur {target}...")
    
    # Parse des ports
    if ports:
        port_list = parse_port_range(ports)
    else:
        port_list = COMMON_PORTS
    
    results = engine.scan_target(target, scan_types=scan_types, ports=port_list)
    print_scan_results(results)
    return results

def list_plugins(engine):
    """Liste les plugins disponibles"""
    print("\n📦 Plugins disponibles:")
    print("-" * 60)
    plugins = engine.plugin_manager.list_plugins()
    for plugin in plugins:
        print(f"\n  Nom: {plugin['name']}")
        print(f"  Description: {plugin['description']}")
        print(f"  Version: {plugin['version']}")
    print("\n")

def show_history(db, limit=10):
    """Affiche l'historique des scans"""
    print(f"\n📜 Historique des {limit} derniers scans:")
    print("-" * 60)
    scans = db.get_all_scans(limit)
    
    if not scans:
        print("  Aucun scan trouvé dans l'historique.")
        return
    
    for scan in scans:
        print(f"\n  ID: {scan['scan_id']}")
        print(f"  Cible: {scan['target']}")
        print(f"  Types: {scan['scan_types']}")
        print(f"  Date: {scan['timestamp']}")
        print(f"  Durée: {scan['duration']}")
        print(f"  Statut: {scan['status']}")
    
    print("\n")

def export_results(results, filename):
    """
    Exporte les résultats en JSON
    
    Args:
        results: Résultats à exporter
        filename: Nom du fichier de sortie
    """
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✅ Résultats exportés vers: {filename}\n")
    except Exception as e:
        print(f"\n❌ Erreur lors de l'export: {e}\n")

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description='NetScope - Mini-Framework de Scan Réseau Modulaire',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s -t 192.168.1.1 --quick                    # Scan rapide
  %(prog)s -t 192.168.1.0/24 --deep                  # Scan approfondi d'un réseau
  %(prog)s -t 192.168.1.1 -p 80,443,8080             # Scan de ports spécifiques
  %(prog)s -t 192.168.1.1 --scan-types TCP_SYN UDP   # Scans personnalisés
  %(prog)s --list-plugins                            # Liste les plugins
  %(prog)s --history                                 # Affiche l'historique
  %(prog)s --web                                     # Lance l'interface web
        """
    )
    
    parser.add_argument('-t', '--target', help='Cible du scan (IP ou range)')
    parser.add_argument('-p', '--ports', help='Ports à scanner (ex: 80,443,8000-9000)')
    parser.add_argument('--quick', action='store_true', help='Scan rapide (ports communs)')
    parser.add_argument('--deep', action='store_true', help='Scan approfondi (tous les plugins)')
    parser.add_argument('--scan-types', nargs='+', help='Types de scans à effectuer')
    parser.add_argument('--list-plugins', action='store_true', help='Liste les plugins disponibles')
    parser.add_argument('--history', action='store_true', help='Affiche l\'historique des scans')
    parser.add_argument('--export', help='Exporte les résultats en JSON')
    parser.add_argument('--web', action='store_true', help='Lance l\'interface web')
    parser.add_argument('--version', action='version', version=f'NetScope v{VERSION}')
    
    args = parser.parse_args()
    
    # Affichage de la bannière
    print_banner()
    
    # Initialisation
    engine = ScanEngine()
    db = DatabaseManager()
    
    print(f"[+] {len(engine.plugin_manager.plugins)} plugin(s) chargé(s)")
    
    # Lancement de l'interface web
    if args.web:
        print("\n[*] Lancement de l'interface web...")
        from web.dashboard import app
        from config.settings import WEB_CONFIG
        app.run(host=WEB_CONFIG['host'], port=WEB_CONFIG['port'], debug=WEB_CONFIG['debug'])
        return
    
    # Liste des plugins
    if args.list_plugins:
        list_plugins(engine)
        return
    
    # Historique
    if args.history:
        show_history(db)
        return
    
    # Vérification de la cible
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    # Exécution du scan
    results = None
    
    if args.quick:
        results = quick_scan(engine, args.target)
    elif args.deep:
        results = deep_scan(engine, args.target)
    elif args.scan_types:
        results = custom_scan(engine, args.target, args.scan_types, args.ports)
    else:
        # Scan par défaut (quick)
        results = quick_scan(engine, args.target)
    
    # Sauvegarde dans la base de données
    if results:
        db.save_scan(results)
        print(f"[+] Résultats sauvegardés (ID: {results.get('scan_id')})")
    
    # Export si demandé
    if args.export and results:
        export_results(results, args.export)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrompu par l'utilisateur.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Erreur: {e}\n")
        sys.exit(1)
