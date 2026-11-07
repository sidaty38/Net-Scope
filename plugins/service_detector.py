"""
Plugin de détection de service avec ML pour NetScope
Utilise des patterns et heuristiques pour identifier les services
"""
import sys
import os
from typing import Dict, Any, List
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.plugin_manager import PluginBase
from core.utils import validate_ip
from config.settings import SERVICE_PATTERNS

class ServiceDetector(PluginBase):
    """Détecteur de services avec ML simple (pattern matching)"""
    
    def __init__(self):
        super().__init__()
        self.name = "SERVICE_DETECTOR"
        self.description = "Détection intelligente de services via ML"
        self.version = "1.0"
        
        # Base de connaissances (simple ML)
        self.knowledge_base = {}
        self.confidence_threshold = 0.6
    
    def get_info(self) -> Dict[str, str]:
        """Retourne les informations du plugin"""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'ml_type': 'Pattern-based classification'
        }
    
    def validate_input(self, target: str) -> bool:
        """Valide l'IP cible"""
        return validate_ip(target)
    
    def train_on_banner(self, banner: str, service: str):
        """
        Entraîne le modèle simple avec une bannière
        
        Args:
            banner: Bannière du service
            service: Nom du service
        """
        if service not in self.knowledge_base:
            self.knowledge_base[service] = []
        
        # Extraction de mots-clés
        keywords = self._extract_keywords(banner)
        self.knowledge_base[service].extend(keywords)
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extrait des mots-clés d'un texte"""
        # Mots communs à ignorer
        stop_words = {'the', 'is', 'at', 'which', 'on', 'a', 'an', 'and', 'or', 'but'}
        
        words = text.lower().split()
        keywords = [w for w in words if len(w) > 2 and w not in stop_words]
        return keywords
    
    def classify_service(self, banner: str, port: int) -> Dict[str, Any]:
        """
        Classifie un service basé sur sa bannière
        
        Args:
            banner: Bannière à classifier
            port: Port du service
            
        Returns:
            Classification avec score de confiance
        """
        if not banner:
            return {
                'service': 'unknown',
                'confidence': 0.0,
                'method': 'no_banner'
            }
        
        # Pattern matching avec les patterns connus
        scores = {}
        banner_lower = banner.lower()
        
        for service, patterns in SERVICE_PATTERNS.items():
            score = 0
            matches = []
            
            for pattern in patterns:
                if pattern.lower() in banner_lower:
                    score += 1
                    matches.append(pattern)
            
            if score > 0:
                scores[service] = {
                    'score': score / len(patterns),  # Normalisation
                    'matches': matches
                }
        
        # Sélection du meilleur candidat
        if scores:
            best_service = max(scores.items(), key=lambda x: x[1]['score'])
            return {
                'service': best_service[0],
                'confidence': best_service[1]['score'],
                'matches': best_service[1]['matches'],
                'method': 'pattern_matching'
            }
        
        # Fallback sur le port
        return self._guess_by_port(port)
    
    def _guess_by_port(self, port: int) -> Dict[str, Any]:
        """Devine le service par le port"""
        port_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        if port in port_services:
            return {
                'service': port_services[port],
                'confidence': 0.5,
                'method': 'port_based'
            }
        
        return {
            'service': 'unknown',
            'confidence': 0.0,
            'method': 'unknown'
        }
    
    def detect_anomalies(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Détecte des anomalies dans les services détectés
        
        Args:
            services: Liste des services
            
        Returns:
            Liste des anomalies détectées
        """
        anomalies = []
        
        # Vérification de services sur ports non standards
        for service in services:
            port = service.get('port')
            detected_service = service.get('service', '').upper()
            
            # Ports standards attendus
            standard_ports = {
                'SSH': 22,
                'HTTP': 80,
                'HTTPS': 443,
                'FTP': 21,
                'MYSQL': 3306
            }
            
            if detected_service in standard_ports:
                if port != standard_ports[detected_service]:
                    anomalies.append({
                        'type': 'non_standard_port',
                        'service': detected_service,
                        'port': port,
                        'expected_port': standard_ports[detected_service],
                        'severity': 'medium',
                        'description': f"{detected_service} sur port non-standard {port}"
                    })
        
        # Vérification de multiples services similaires
        service_types = [s.get('service') for s in services]
        service_counts = Counter(service_types)
        
        for service, count in service_counts.items():
            if count > 2 and service != 'unknown':
                anomalies.append({
                    'type': 'multiple_instances',
                    'service': service,
                    'count': count,
                    'severity': 'low',
                    'description': f"Plusieurs instances de {service} détectées ({count})"
                })
        
        return anomalies
    
    def generate_security_score(self, services: List[Dict[str, Any]], 
                               vulnerabilities: List[str]) -> Dict[str, Any]:
        """
        Génère un score de sécurité basé sur les services détectés
        
        Args:
            services: Services détectés
            vulnerabilities: Vulnérabilités trouvées
            
        Returns:
            Score de sécurité et recommandations
        """
        from config.settings import SECURITY_THRESHOLDS
        
        score = 100
        issues = []
        
        # Pénalités pour services à risque
        for service in services:
            port = service.get('port')
            if port in SECURITY_THRESHOLDS['high_risk_ports']:
                score -= 15
                issues.append(f"Port à haut risque ouvert: {port}")
        
        # Pénalités pour vulnérabilités
        score -= len(vulnerabilities) * 10
        
        # Pénalités pour services non identifiés
        unknown_services = [s for s in services if s.get('service') == 'unknown']
        score -= len(unknown_services) * 5
        
        score = max(0, score)  # Minimum 0
        
        # Détermination du niveau
        if score >= 80:
            level = 'GOOD'
            color = 'green'
        elif score >= 60:
            level = 'MEDIUM'
            color = 'orange'
        else:
            level = 'LOW'
            color = 'red'
        
        return {
            'score': score,
            'level': level,
            'color': color,
            'issues': issues,
            'total_services': len(services),
            'total_vulnerabilities': len(vulnerabilities)
        }
    
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Exécute la détection de services
        
        Args:
            target: IP cible
            **kwargs: banner_results (résultats du banner grabbing)
            
        Returns:
            Résultats de la détection
        """
        # Récupération des résultats du banner grabbing
        banner_results = kwargs.get('banner_results', {})
        services_data = banner_results.get('services', [])
        vulnerabilities = banner_results.get('vulnerabilities', [])
        
        results = {
            'ip': target,
            'detected_services': [],
            'anomalies': [],
            'security_score': {},
            'scan_type': 'ML Service Detection'
        }
        
        # Classification de chaque service
        for service_data in services_data:
            banner = service_data.get('banner', '')
            port = service_data.get('port')
            
            classification = self.classify_service(banner, port)
            classification['port'] = port
            classification['original_banner'] = banner[:100]
            
            results['detected_services'].append(classification)
        
        # Détection d'anomalies
        if results['detected_services']:
            results['anomalies'] = self.detect_anomalies(results['detected_services'])
        
        # Score de sécurité
        results['security_score'] = self.generate_security_score(
            results['detected_services'],
            vulnerabilities
        )
        
        results['summary'] = f"{len(results['detected_services'])} services analysés, "
        results['summary'] += f"Score de sécurité: {results['security_score']['score']}/100"
        
        return results
