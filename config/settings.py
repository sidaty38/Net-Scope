"""
Configuration du framework NetScope
"""

# Configuration générale
DEBUG = True
VERSION = "1.0.0"

# Configuration des scans
SCAN_CONFIG = {
    'timeout': 3.0,
    'max_threads': 50,
    'max_retries': 2,
    'delay_between_scans': 0.01  # secondes
}

# Ports communs à scanner
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
    3306, 3389, 5432, 5900, 8080, 8443, 27017
]

# Configuration de la base de données
DATABASE = {
    'path': 'storage/netscope.db'
}

# Configuration du serveur web
WEB_CONFIG = {
    'host': '0.0.0.0',
    'port': 5000,
    'debug': DEBUG
}

# Patterns de services (pour ML simple)
SERVICE_PATTERNS = {
    'SSH': ['SSH', 'OpenSSH'],
    'HTTP': ['HTTP', 'Apache', 'nginx', 'Server:'],
    'FTP': ['FTP', '220'],
    'MySQL': ['mysql', 'MySQL'],
    'PostgreSQL': ['PostgreSQL'],
    'MongoDB': ['MongoDB'],
    'Redis': ['Redis'],
    'SMTP': ['SMTP', '220'],
}

# Seuils de sécurité
SECURITY_THRESHOLDS = {
    'high_risk_ports': [23, 445, 3389],  # Telnet, SMB, RDP
    'outdated_versions': ['Apache/2.2', 'OpenSSH_5'],
    'suspicious_banners': ['default', 'test', 'admin']
}
