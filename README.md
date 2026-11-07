# 🔍 NetScope - Smart Network Intelligence & Security Scanner

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-production--ready-success.svg)

**Mini-Framework de Scan Réseau Modulaire avec Machine Learning**

[Installation](#-installation-rapide) •
[Guide d'utilisation](#-guide-dutilisation) •
[Fonctionnalités](#-fonctionnalités-principales) •
[Documentation](#-documentation)

</div>

---

## 📖 Table des Matières

- [Présentation](#-présentation)
- [Fonctionnalités](#-fonctionnalités-principales)
- [Architecture](#-architecture)
- [Installation](#-installation-rapide)
- [Guide d'utilisation](#-guide-dutilisation)
- [Plugins](#-plugins-disponibles)
- [Dashboard Web](#-dashboard-web)
- [Exemples](#-exemples)
- [FAQ](#-faq)
- [Contribution](#-contribution)

---

## 🎯 Présentation

NetScope est un **framework de scan réseau modulaire** développé en Python qui combine des techniques de scan classiques avec de l'intelligence artificielle pour analyser les réseaux et détecter les vulnérabilités potentielles.

### 🎓 Contexte

Ce projet a été développé dans le cadre d'un TP de sécurité réseau pour démontrer :
- La compréhension des protocoles réseau (TCP, UDP, HTTP, SSL/TLS)
- L'implémentation de techniques de scan avancées (banner grabbing, fingerprinting)
- L'application du Machine Learning à la cybersécurité
- Le développement d'une architecture modulaire (plugins)

### 🌟 Points Forts

- ✅ **Architecture modulaire** - Système de plugins extensible
- ✅ **Interface web intuitive** - Dashboard moderne avec statistiques en temps réel
- ✅ **3 modes de scan** - Quick (5-10s), Deep (30-60s), Custom (variable)
- ✅ **Support DNS** - Scan par IP ou nom de domaine
- ✅ **Machine Learning** - Détection intelligente de services et anomalies
- ✅ **Banner grabbing avancé** - 7 techniques différentes (multi-probes, SSL, headers...)
- ✅ **Scoring de sécurité** - Évaluation automatique avec recommandations

---

## 🚀 Fonctionnalités Principales

### 1. Trois Modes de Scan

| Mode | Durée | Techniques | Usage |
|------|-------|------------|-------|
| **Quick Scan ⚡** | 5-10s | TCP SYN + Banner Grabbing | Découverte rapide |
| **Deep Scan 🔍** | 30-60s | TCP + UDP + Banner Avancé + ML + Sécurité | Analyse complète |
| **Custom Scan 🎨** | Variable | Ports et techniques au choix | Sur-mesure |

### 2. Techniques de Scan Avancées

#### 🔹 Banner Grabbing Ultra-Avancé
- **Multi-probes HTTP** - 5 types de requêtes différentes
- **Inspection SSL/TLS** - Extraction infos certificat
- **Headers secondaires** - X-Powered-By, X-Backend-Server...
- **Fingerprinting comportemental** - Détection par patterns d'erreur
- **Timeouts adaptatifs** - Optimisation pour serveurs lents

#### 🔹 Détection par Machine Learning
- **Classification de services** - Pattern matching intelligent
- **Détection d'anomalies** - Ports non-standard, configurations suspectes
- **Score de sécurité** - Évaluation 0-100 avec code couleur
- **Recommandations** - Suggestions d'amélioration

### 3. Dashboard Web Moderne

<div align="center">

```
╔══════════════════════════════════════════════════════════╗
║                    🔍 NetScope                           ║
║        Smart Network Intelligence & Security Scanner      ║
╚══════════════════════════════════════════════════════════╝

┌─────────────┬─────────────┬─────────────┬─────────────┐
│ Scans: 29   │ Hôtes: 6    │ Ports: 71   │ Alertes: 0  │
└─────────────┴─────────────┴─────────────┴─────────────┘
```

</div>

**Fonctionnalités du dashboard :**
- 📊 Statistiques en temps réel
- 🎨 Interface responsive et moderne
- 🌐 Support IP et noms de domaine
- 📄 Bannières complètes avec bouton "Voir plus"
- 🔒 Infos SSL/TLS détaillées
- 📋 Headers HTTP révélateurs
- ⚠️ Anomalies et vulnérabilités
- 🎯 Score de sécurité visuel

### 4. Stockage et Historique

- 💾 Base de données SQLite
- 📜 Historique complet des scans
- 📊 Statistiques globales
- 🔍 Recherche par hôte
- 📤 Export JSON

---

## 🏗️ Architecture

```
netscope/
│
├── 📂 core/                    # Cœur du framework
│   ├── engine.py              # Moteur de scan principal
│   ├── plugin_manager.py      # Gestionnaire de plugins
│   └── utils.py               # Utilitaires (IP, ports, checksums...)
│
├── 📂 plugins/                 # Plugins de scan
│   ├── tcp_syn_scanner.py     # Scanner TCP SYN
│   ├── udp_scanner.py         # Scanner UDP
│   ├── banner_grabber.py      # Banner grabbing avancé
│   └── service_detector.py    # Détection ML + Sécurité
│
├── 📂 web/                     # Interface web
│   ├── dashboard.py           # API REST Flask
│   └── templates/
│       └── index.html         # Interface utilisateur
│
├── 📂 storage/                 # Persistance
│   ├── database.py            # Gestionnaire BDD SQLite
│   └── netscope.db           # Base de données
│
├── 📂 config/                  # Configuration
│   └── settings.py            # Paramètres globaux
│
├── 📂 tests/                   # Tests
│   └── test_lab.py           # Environnement de test
│
├── main.py                    # Point d'entrée CLI
├── quickstart.sh              # Menu interactif
└── requirements.txt           # Dépendances Python
```

### Architecture Modulaire

Le framework utilise un **système de plugins** basé sur une classe abstraite `PluginBase` :

```python
class PluginBase(ABC):
    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Méthode principale du plugin"""
        pass
```

**Avantages :**
- ✅ Ajout facile de nouveaux scanners
- ✅ Désactivation/activation à la volée
- ✅ Isolation des erreurs
- ✅ Testabilité individuelle

---

## 💻 Installation Rapide

### Prérequis

- **Python 3.8+** (testé sur 3.8, 3.9, 3.10, 3.12)
- **pip** (gestionnaire de paquets Python)
- **Linux/Unix** (testé sur Ubuntu 24, Kali, Debian)

### Installation en 3 Étapes

```bash
# 1. Cloner ou extraire le projet
cd ~/Téléchargements
unzip netscope.zip  # ou git clone ...
cd netscope

# 2. Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate

# 3. Installer les dépendances
pip install -r requirements.txt
```

### Vérification de l'Installation

```bash
# Test rapide
python3 main.py --help

# Devrait afficher :
# ╔════════════════════════════════════════════════════════════╗
# ║              🔍 NetScope v1.0.0                         ║
# ╚════════════════════════════════════════════════════════════╝
```

---

## 📚 Guide d'Utilisation

### Option 1 : Menu Interactif (Recommandé pour débuter)

```bash
./quickstart.sh
```

**Menu principal :**
```
════════════════ MENU PRINCIPAL ════════════════

  [1] 🔧 Installation & Configuration
  [2] 🚀 Lancer un Scan
  [3] 🌐 Dashboard Web
  [4] 🧪 Environnement de Test
  [5] 📊 Historique & Statistiques
  [6] 🔌 Gestion des Plugins
  [7] 📖 Documentation & Aide
  [8] ⚙️  Configuration Avancée
  [9] 🚪 Quitter
```

### Option 2 : Ligne de Commande (CLI)

#### Quick Scan (Rapide - 5-10s)

```bash
# Scan d'une IP
python3 main.py -t 192.168.1.1 --quick

# Scan d'un domaine
python3 main.py -t google.com --quick
```

**Résultat :**
```
⚡ QUICK SCAN - Découverte Rapide
════════════════════════════════════════════════
Ports scannés: 17 ports communs
Techniques: TCP SYN + Banner Grabbing
════════════════════════════════════════════════

[+] Exécution de TCP_SYN sur 192.168.1.1
    ✓ Port 80 ouvert (HTTP)
    ✓ Port 443 ouvert (HTTPS)

[+] Exécution de BANNER_GRABBER sur 192.168.1.1
    ✓ Bannière récupérée sur port 80

Durée: 5.04s
```

#### Deep Scan (Complet - 30-60s)

```bash
# Analyse complète avec ML et sécurité
python3 main.py -t 192.168.1.1 --deep
```

**Résultat :**
```
🔍 DEEP SCAN - Analyse Complète
════════════════════════════════════════════════
Ports scannés: 17 ports TCP + 11 ports UDP
Techniques: TCP + UDP + Banner Advanced + ML + Sécurité
════════════════════════════════════════════════

[+] Exécution de TCP_SYN
[+] Exécution de UDP_SCANNER
[+] Exécution de BANNER_GRABBER
[+] Exécution de SERVICE_DETECTOR

Score de sécurité: 85/100 (GOOD)
Anomalies détectées: 1
Vulnérabilités: 0

Durée: 56.68s
```

#### Custom Scan (Personnalisé)

```bash
# Ports spécifiques
python3 main.py -t 192.168.1.1 -p 80,443,8000-9000

# Techniques spécifiques
python3 main.py -t 192.168.1.1 --scan-types TCP_SYN BANNER_GRABBER
```

#### Scan d'un Range

```bash
# Scan d'un sous-réseau
python3 main.py -t 192.168.1.0/24 --quick
```

### Option 3 : Dashboard Web

```bash
# Lancer le serveur web
python3 main.py --web

# Ouvrir dans le navigateur
# http://localhost:5000
```

**Interface web :**
- 🎯 Formulaire de scan interactif
- 📊 Statistiques en temps réel
- 🔍 Résultats détaillés avec bannières complètes
- 📄 Bouton "Voir plus" pour bannières longues
- 🌐 Support noms de domaine
- 🎨 Design moderne et responsive

### Option 4 : Environnement de Test

Pour tester NetScope sans scanner un réseau réel :

```bash
# Terminal 1 : Lancer l'environnement de test
python3 tests/test_lab.py

# Terminal 2 : Scanner localhost
python3 main.py -t 127.0.0.1 --deep
```

**Services simulés :**
- Port 2222 : SSH (OpenSSH 8.9)
- Port 8080 : HTTP (nginx 1.18.0)
- Port 3307 : MySQL (5.7.32)

---

## 🔌 Plugins Disponibles

### 1. TCP_SYN - Scanner TCP

**Description :** Scanner de ports TCP utilisant la méthode connect.

**Fonctionnalités :**
- ✅ Scan multithread (50 threads par défaut)
- ✅ Détection état : open, closed, filtered
- ✅ Identification service par port
- ✅ Timeout configurable

**Usage :**
```bash
python3 main.py -t 192.168.1.1 --scan-types TCP_SYN -p 1-1000
```

### 2. UDP_SCANNER - Scanner UDP

**Description :** Scanner de ports UDP.

**Fonctionnalités :**
- ✅ Scan de 11 ports UDP communs (DNS, NTP, SNMP...)
- ✅ Détection : open, closed, open|filtered
- ✅ Identification service

**Ports par défaut :**
```
53 (DNS), 67-68 (DHCP), 69 (TFTP), 123 (NTP),
161-162 (SNMP), 500 (IKE), 514 (Syslog), 1900 (SSDP)
```

**Usage :**
```bash
python3 main.py -t 192.168.1.1 --scan-types UDP_SCANNER
```

### 3. BANNER_GRABBER - Banner Grabbing Avancé

**Description :** Récupération avancée des bannières de service.

**7 Techniques :**

1. **Multi-probes HTTP** (5 requêtes)
   - GET normal
   - OPTIONS
   - HEAD
   - Requête invalide (provoque erreur)
   - HTTP/1.0

2. **Headers secondaires**
   - X-Powered-By
   - X-Backend-Server
   - X-AspNet-Version
   - Via, X-Generator...

3. **Inspection SSL/TLS**
   - Common Name (CN)
   - Organization
   - TLS version
   - Dates validité

4. **Fingerprinting par erreur**
   - Patterns Apache
   - Patterns nginx
   - Patterns IIS

5. **Fichiers spéciaux**
   - robots.txt
   - server-status
   - phpinfo.php

6. **Timeouts adaptatifs**
   - 3.0s au lieu de 1.0s

7. **Behavioral fingerprinting**
   - Analyse comportement serveur

**Résultat :**
```json
{
  "port": 443,
  "service": "nginx",
  "version": "nginx/1.18.0",
  "confidence": "high",
  "collection_method": ["Server header", "SSL certificate"],
  "ssl_info": {
    "common_name": "example.com",
    "tls_version": "TLSv1.3"
  },
  "http_headers": {
    "x-powered-by": "PHP/7.4.3"
  }
}
```

**Usage :**
```bash
python3 main.py -t 192.168.1.1 --scan-types TCP_SYN BANNER_GRABBER
```

### 4. SERVICE_DETECTOR - Machine Learning

**Description :** Détection intelligente de services et analyse sécurité.

**Fonctionnalités :**

1. **Classification ML**
   - Pattern matching avancé
   - Score de confiance
   - Méthode de détection

2. **Détection d'anomalies**
   - Services sur ports non-standard
   - Instances multiples
   - Configurations suspectes

3. **Score de sécurité** (0-100)
   - Évaluation globale
   - Niveau : GOOD / MEDIUM / LOW
   - Code couleur : 🟢 / 🟠 / 🔴

4. **Recommandations**
   - Ports à haut risque
   - Versions obsolètes
   - Problèmes détectés

**Exemple de résultat :**
```
Score de Sécurité: 85/100 (GOOD)

Problèmes identifiés:
• Port à haut risque ouvert: 3389 (RDP)

Anomalies détectées:
• MEDIUM SSH sur port non-standard 2222
• LOW Plusieurs instances de HTTP détectées (2)
```

**Usage :**
```bash
python3 main.py -t 192.168.1.1 --deep  # Inclut SERVICE_DETECTOR
```

---

## 🌐 Dashboard Web

### Lancement

```bash
python3 main.py --web
```

### Accès

Ouvrir dans un navigateur : **http://localhost:5000**

### Fonctionnalités

#### 1. Statistiques en Temps Réel

```
┌─────────────┬─────────────┬─────────────┬─────────────┐
│ Scans: 29   │ Hôtes: 6    │ Ports: 71   │ Alertes: 0  │
└─────────────┴─────────────┴─────────────┴─────────────┘
```

#### 2. Formulaire de Scan

- **Cible :** IP ou nom de domaine
- **Type :** Quick / Deep / Custom
- **Ports :** Optionnel (ex: 80,443,8000-9000)
- **Explication dynamique** du type de scan sélectionné

#### 3. Affichage des Résultats

**Informations générales :**
- Scan ID
- Cible (avec résolution DNS si domaine)
- Types de scan effectués
- Durée d'exécution

**Score de sécurité :**
```
╔═══════════════════════════════════════╗
║  85/100   Score de Sécurité: GOOD    ║
║           4 services • 0 vulns       ║
╚═══════════════════════════════════════╝

⚠️ Problèmes identifiés:
• Port à haut risque ouvert: 3389
```

**Anomalies :**
```
🔍 Anomalies Détectées:
• MEDIUM SSH sur port non-standard 2222
• LOW Plusieurs instances de HTTP (2)
```

**Ports TCP :**

| Port | État | Service | Version | Confiance | Bannière |
|------|------|---------|---------|-----------|----------|
| 80 | open | nginx | nginx/1.18.0 | high | HTTP/1.1 301... [📄 Voir plus] |
| 443 | open | nginx | nginx/1.18.0 | high | HTTP/1.1 200... [📄 Voir plus] |

**Ports UDP :**

| Port | État | Service |
|------|------|---------|
| 53 | open\|filtered | DNS |
| 123 | open\|filtered | NTP |

**Bannières complètes :**
- Affichage initial : 80 premiers caractères
- Bouton "Voir plus" pour afficher la bannière entière
- Scrollbar si bannière > 400px
- Infos SSL/TLS si HTTPS
- Headers HTTP révélateurs

---

## 📝 Exemples d'Utilisation

### Exemple 1 : Audit de Sécurité d'un Serveur Web

```bash
# 1. Scan initial rapide
python3 main.py -t www.example.com --quick

# 2. Analyse approfondie
python3 main.py -t www.example.com --deep

# 3. Export des résultats
python3 main.py -t www.example.com --deep --export results.json
```

**Résultat attendu :**
- Ports ouverts (80, 443)
- Versions des services (Apache 2.4.41, OpenSSL 1.1.1)
- Score de sécurité
- Recommandations

### Exemple 2 : Scan d'un Réseau Local

```bash
# 1. Scanner le sous-réseau
python3 main.py -t 192.168.1.0/24 --quick

# 2. Voir l'historique
python3 main.py --history

# 3. Statistiques
./quickstart.sh
# Choisir option 5
```

### Exemple 3 : Test d'un Nouveau Service

```bash
# 1. Lancer l'environnement de test
python3 tests/test_lab.py

# 2. Dans un autre terminal, scanner
python3 main.py -t 127.0.0.1 --deep

# 3. Vérifier les résultats
# Devrait détecter : SSH (2222), HTTP (8080), MySQL (3307)
```

### Exemple 4 : Scan Custom avec Ports Spécifiques

```bash
# Scanner uniquement les ports web
python3 main.py -t example.com -p 80,443,8080,8443 --scan-types TCP_SYN BANNER_GRABBER
```

### Exemple 5 : Utilisation du Dashboard

```bash
# 1. Lancer le dashboard
python3 main.py --web

# 2. Dans le navigateur (http://localhost:5000)
#    - Entrer : google.com
#    - Sélectionner : Deep Scan
#    - Cliquer : Scanner

# 3. Observer les résultats :
#    - Résolution DNS : google.com → 142.250.185.46
#    - Score de sécurité
#    - Bannières complètes
#    - Infos SSL/TLS
```

---

## 🔧 Configuration

### Fichier : `config/settings.py`

```python
# Configuration des scans
SCAN_CONFIG = {
    'timeout': 3.0,         # Timeout par connexion
    'max_threads': 50,      # Threads simultanés
    'max_retries': 2,       # Tentatives
    'delay_between_scans': 0.01  # Délai entre scans
}

# Ports communs (Quick Scan)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
    3306, 3389, 5432, 5900, 8080, 8443, 27017
]

# Configuration web
WEB_CONFIG = {
    'host': '0.0.0.0',     # Écouter sur toutes les interfaces
    'port': 5000,          # Port du serveur
    'debug': False         # Mode debug (dev)
}
```

**Modifier la configuration :**

```bash
nano config/settings.py
# Modifier les valeurs
# Sauvegarder : Ctrl+O, Ctrl+X
```

---

## 📊 Base de Données

### Structure

NetScope utilise **SQLite** pour stocker l'historique des scans.

**Tables :**

1. **scans** - Scans effectués
   - scan_id, target, scan_types, timestamp, duration, results_json

2. **hosts** - Hôtes découverts
   - ip, hostname, first_seen, last_seen

3. **ports** - Ports ouverts
   - ip, port, protocol, state, service, version, banner

4. **vulnerabilities** - Vulnérabilités détectées
   - ip, port, vulnerability, severity, description

5. **alerts** - Alertes système
   - alert_type, target, description, severity

### Commandes Utiles

```bash
# Voir l'historique
python3 main.py --history

# Voir un scan spécifique
python3 -c "
from storage.database import DatabaseManager
db = DatabaseManager()
scan = db.get_scan('scan_1707306330')
print(scan)
"

# Réinitialiser la base
rm storage/netscope.db
# Elle sera recréée au prochain scan
```

---

## 🛡️ Sécurité et Légalité

### ⚠️ IMPORTANT - Utilisation Légale

**NetScope est un outil pédagogique.**

✅ **Utilisations autorisées :**
- Vos propres systèmes et réseaux
- Environnements de test/lab
- Avec autorisation écrite du propriétaire
- Dans le cadre de formations officielles

❌ **Utilisations interdites :**
- Scanner des systèmes sans autorisation
- Exploiter des vulnérabilités découvertes
- Causer des dénis de service
- Violer la vie privée

**Responsabilité :**
L'auteur et les contributeurs ne sont pas responsables de l'utilisation malveillante de cet outil.

### 🔒 Bonnes Pratiques

1. **Obtenir une autorisation écrite** avant tout scan
2. **Limiter le taux de scan** pour ne pas surcharger les cibles
3. **Respecter les heures ouvrables** pour les environnements de production
4. **Logger toutes les activités** pour l'audit
5. **Ne jamais exploiter** les vulnérabilités trouvées sans autorisation

---

## ❓ FAQ

### Q1 : NetScope fonctionne-t-il sur Windows ?

**R :** NetScope est conçu pour Linux/Unix. Sur Windows, utilisez WSL (Windows Subsystem for Linux) :

```bash
# Dans WSL
cd /mnt/c/Users/VotreNom/Downloads
unzip netscope.zip
cd netscope
python3 main.py --help
```

### Q2 : Pourquoi certaines bannières sont "N/A" ?

**R :** Les serveurs modernes masquent souvent leurs bannières pour des raisons de sécurité. NetScope utilise 7 techniques avancées pour récupérer un maximum d'informations, mais certains serveurs restent silencieux.

**Solutions :**
- Utiliser Deep Scan (plus de techniques)
- Les infos SSL/TLS sont généralement disponibles même si la bannière HTTP est masquée
- Analyser les headers secondaires (X-Powered-By, etc.)

### Q3 : Le scan est lent, comment l'accélérer ?

**R :** Modifier `config/settings.py` :

```python
SCAN_CONFIG = {
    'timeout': 1.0,        # Réduire de 3.0 à 1.0
    'max_threads': 100,    # Augmenter de 50 à 100
}
```

**Attention :** Augmenter trop les threads peut causer des faux positifs.

### Q4 : Comment ajouter un nouveau plugin ?

**R :** Créer un fichier dans `plugins/` :

```python
# plugins/mon_scanner.py
from core.plugin_manager import PluginBase

class MonScanner(PluginBase):
    def __init__(self):
        super().__init__()
        self.name = "MON_SCANNER"
        
    def run(self, target, **kwargs):
        # Votre code ici
        return {'result': 'OK'}
    
    def get_info(self):
        return {'name': self.name, 'description': 'Mon scanner'}
```

Le plugin sera automatiquement chargé au démarrage.

### Q5 : Le dashboard ne se lance pas

**R :** Vérifier :

```bash
# Flask installé ?
pip show flask

# Port 5000 libre ?
lsof -i :5000

# Tester avec un autre port
# Dans config/settings.py
WEB_CONFIG = {
    'port': 8080  # Au lieu de 5000
}
```

### Q6 : Les ports UDP ne sont pas détectés

**R :** Les scans UDP sont moins fiables que TCP. Raisons :
- UDP ne répond pas toujours
- Firewalls filtrent souvent l'UDP
- Certains services UDP nécessitent des payloads spécifiques

**Solution :** Le scan UDP détecte "open|filtered" quand incertain.

### Q7 : Comment exporter les résultats ?

**R :**

```bash
# Export JSON
python3 main.py -t 192.168.1.1 --deep --export results.json

# Lire le JSON
cat results.json | python3 -m json.tool
```

### Q8 : NetScope nécessite-t-il root ?

**R :** **Non**, NetScope utilise des connexions TCP/UDP normales (pas de raw sockets). Aucun privilège root requis.

---

## 🐛 Dépannage

### Erreur : "cannot import name 'DatabaseManager'"

**Solution :**
```bash
# Vérifier que la classe est bien nommée
grep "class DatabaseManager" storage/database.py

# Si c'est "class Database", renommer
sed -i 's/class Database:/class DatabaseManager:/' storage/database.py
```

### Erreur : "calculate_scan_duration() takes 1 positional argument but 2 were given"

**Solution :**
```bash
# Vérifier la signature dans core/utils.py
# Doit être :
def calculate_scan_duration(start_time: float, end_time: float) -> str:
```

### Erreur : "No module named 'flask'"

**Solution :**
```bash
# Activer le venv
source venv/bin/activate

# Installer flask
pip install flask

# NE PAS utiliser sudo python3
```

---

## 🎓 Pour Aller Plus Loin

### Documentation Technique

- `docs/ARCHITECTURE.md` - Architecture détaillée
- `docs/PLUGINS.md` - Guide de développement de plugins
- `docs/API.md` - Documentation API REST
- `CORRECTIONS_COMPLETES.md` - Journal des corrections

### Ressources Externes

- [Nmap Documentation](https://nmap.org/book/) - Référence pour les techniques de scan
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Guide de sécurité web
- [CVE Database](https://cve.mitre.org/) - Base de vulnérabilités
- [Python Socket Programming](https://docs.python.org/3/library/socket.html) - Documentation officielle

### Améliorations Futures

Idées pour étendre NetScope :

1. **Scan IPv6** - Support complet d'IPv6
2. **Scan scriptable** - Scripts NSE-like
3. **Reporting** - Génération de rapports PDF/HTML
4. **Integration API** - Shodan, VirusTotal, etc.
5. **Détection OS** - Fingerprinting OS via TTL, fenêtre TCP
6. **Fuzzing** - Test de robustesse des services

---

## 👥 Contribution

### Comment Contribuer

1. **Fork** le projet
2. **Créer une branche** : `git checkout -b feature/ma-fonctionnalite`
3. **Commit** : `git commit -m 'Ajout de ma fonctionnalité'`
4. **Push** : `git push origin feature/ma-fonctionnalite`
5. **Pull Request** : Ouvrir une PR avec description détaillée

### Guidelines

- **Code** : Suivre PEP 8
- **Docstrings** : Format Google
- **Tests** : Tester avant de commit
- **Documentation** : Mettre à jour le README si nécessaire

---

## 📄 License

Ce projet est sous licence **MIT** - voir le fichier [LICENSE](LICENSE) pour plus de détails.

```
MIT License

Copyright (c) 2026 NetScope Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## ✨ Remerciements

- **Nmap** - Inspiration pour les techniques de scan
- **Flask** - Framework web
- **SQLite** - Base de données légère
- **Communauté Python** - Écosystème riche

---

## 📧 Contact & Support

- **Issues** : [GitHub Issues](https://github.com/votre-username/netscope/issues)
- **Email** : support@netscope.dev
- **Documentation** : [docs.netscope.dev](https://docs.netscope.dev)

---

<div align="center">

**🔍 NetScope - Smart Network Intelligence & Security Scanner**

Développé avec ❤️ pour l'apprentissage de la cybersécurité

[⬆ Retour en haut](#-netscope---smart-network-intelligence--security-scanner)

</div>
