"""
Module de base de données pour NetScope
Stockage et historique des scans
VERSION CORRIGÉE - Gestion robuste de scan_types
"""
import sqlite3
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

class DatabaseManager:
    """Gestionnaire de base de données SQLite"""
    
    def __init__(self, db_path: str = "storage/netscope.db"):
        self.db_path = db_path
        self._ensure_db_directory()
        self.init_database()
    
    def _ensure_db_directory(self):
        """Crée le répertoire de la base de données si nécessaire"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
    
    def init_database(self):
        """Initialise la base de données avec les tables nécessaires"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table des scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_types TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                duration TEXT,
                status TEXT,
                results_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table des hôtes découverts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                ip TEXT NOT NULL,
                hostname TEXT,
                os_guess TEXT,
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        # Table des ports
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                state TEXT,
                service TEXT,
                version TEXT,
                banner TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        # Table des vulnérabilités
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                ip TEXT NOT NULL,
                port INTEGER,
                vulnerability TEXT,
                severity TEXT,
                description TEXT,
                detected_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        ''')
        
        # Table des alertes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                target TEXT,
                description TEXT,
                severity TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, scan_data: Dict[str, Any]) -> bool:
        """
        Sauvegarde un scan dans la base de données
        VERSION CORRIGÉE - Gestion robuste de scan_types
        
        Args:
            scan_data: Données du scan
            
        Returns:
            True si succès
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # CORRECTION : Gestion robuste de scan_types
            scan_types = scan_data.get('scan_types', [])
            if isinstance(scan_types, str):
                # Si c'est déjà une string, l'utiliser directement
                scan_types_str = scan_types
            elif isinstance(scan_types, list):
                # Si c'est une liste, joindre avec des virgules
                scan_types_str = ','.join(scan_types)
            else:
                # Fallback
                scan_types_str = str(scan_types)
            
            cursor.execute('''
                INSERT INTO scans (scan_id, target, scan_types, timestamp, 
                                  duration, status, results_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_data.get('scan_id'),
                scan_data.get('target'),
                scan_types_str,  # CORRIGÉ
                scan_data.get('timestamp'),
                scan_data.get('duration', ''),
                'completed',
                json.dumps(scan_data)
            ))
            
            # Sauvegarde des détails
            for result in scan_data.get('results', []):
                ip = result.get('ip')
                hostname = result.get('hostname', ip)
                
                # Sauvegarde de l'hôte
                cursor.execute('''
                    INSERT INTO hosts (scan_id, ip, hostname, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    scan_data.get('scan_id'),
                    ip,
                    hostname,
                    scan_data.get('timestamp'),
                    scan_data.get('timestamp')
                ))
                
                # Sauvegarde des ports (si scan TCP)
                tcp_scan = result.get('scans', {}).get('TCP_SYN', {})
                for port_info in tcp_scan.get('open_ports', []):
                    cursor.execute('''
                        INSERT INTO ports (scan_id, ip, port, protocol, state, service)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_data.get('scan_id'),
                        ip,
                        port_info.get('port'),
                        'TCP',
                        port_info.get('state'),
                        port_info.get('service')
                    ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"[!] Erreur lors de la sauvegarde du scan: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Récupère un scan par son ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT results_json FROM scans WHERE scan_id = ?', (scan_id,))
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                return json.loads(result[0])
            return None
            
        except Exception as e:
            print(f"[!] Erreur lors de la récupération du scan: {e}")
            return None
    
    def get_all_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Récupère tous les scans (limité)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT scan_id, target, scan_types, timestamp, duration, status
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))
            
            scans = []
            for row in cursor.fetchall():
                scans.append({
                    'scan_id': row[0],
                    'target': row[1],
                    'scan_types': row[2],
                    'timestamp': row[3],
                    'duration': row[4],
                    'status': row[5]
                })
            
            conn.close()
            return scans
            
        except Exception as e:
            print(f"[!] Erreur lors de la récupération des scans: {e}")
            return []
    
    def get_host_history(self, ip: str) -> List[Dict[str, Any]]:
        """Récupère l'historique d'un hôte"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT scan_id, first_seen, last_seen
                FROM hosts
                WHERE ip = ?
                ORDER BY first_seen DESC
            ''', (ip,))
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'scan_id': row[0],
                    'first_seen': row[1],
                    'last_seen': row[2]
                })
            
            conn.close()
            return history
            
        except Exception as e:
            print(f"[!] Erreur lors de la récupération de l'historique: {e}")
            return []
    
    def get_open_ports_for_host(self, ip: str, scan_id: str = None) -> List[Dict[str, Any]]:
        """Récupère les ports ouverts pour un hôte"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if scan_id:
                cursor.execute('''
                    SELECT port, protocol, state, service, version, banner
                    FROM ports
                    WHERE ip = ? AND scan_id = ? AND state = 'open'
                    ORDER BY port
                ''', (ip, scan_id))
            else:
                cursor.execute('''
                    SELECT port, protocol, state, service, version, banner
                    FROM ports
                    WHERE ip = ? AND state = 'open'
                    ORDER BY port
                    LIMIT 100
                ''', (ip,))
            
            ports = []
            for row in cursor.fetchall():
                ports.append({
                    'port': row[0],
                    'protocol': row[1],
                    'state': row[2],
                    'service': row[3],
                    'version': row[4],
                    'banner': row[5]
                })
            
            conn.close()
            return ports
            
        except Exception as e:
            print(f"[!] Erreur lors de la récupération des ports: {e}")
            return []
    
    def create_alert(self, alert_type: str, target: str, 
                    description: str, severity: str = 'medium') -> bool:
        """Crée une alerte"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (alert_type, target, description, severity)
                VALUES (?, ?, ?, ?)
            ''', (alert_type, target, description, severity))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"[!] Erreur lors de la création de l'alerte: {e}")
            return False
    
    def get_unread_alerts(self) -> List[Dict[str, Any]]:
        """Récupère les alertes non lues"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, alert_type, target, description, severity, created_at
                FROM alerts
                WHERE read = 0
                ORDER BY created_at DESC
            ''')
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    'id': row[0],
                    'type': row[1],
                    'target': row[2],
                    'description': row[3],
                    'severity': row[4],
                    'created_at': row[5]
                })
            
            conn.close()
            return alerts
            
        except Exception as e:
            print(f"[!] Erreur lors de la récupération des alertes: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Génère des statistiques sur les scans"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Nombre total de scans
            cursor.execute('SELECT COUNT(*) FROM scans')
            total_scans = cursor.fetchone()[0]
            
            # Nombre total d'hôtes uniques
            cursor.execute('SELECT COUNT(DISTINCT ip) FROM hosts')
            total_hosts = cursor.fetchone()[0]
            
            # Nombre total de ports ouverts
            cursor.execute('SELECT COUNT(*) FROM ports WHERE state = "open"')
            total_open_ports = cursor.fetchone()[0]
            
            # Nombre d'alertes non lues
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE read = 0')
            unread_alerts = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_scans': total_scans,
                'total_hosts': total_hosts,
                'total_open_ports': total_open_ports,
                'unread_alerts': unread_alerts
            }
            
        except Exception as e:
            print(f"[!] Erreur lors de la génération des statistiques: {e}")
            return {
                'total_scans': 0,
                'total_hosts': 0,
                'total_open_ports': 0,
                'unread_alerts': 0
            }
