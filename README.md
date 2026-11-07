# NetScope - Smart Network Intelligence & Security Scanner

Version 1.0.0

## Table des Matieres

1. [Introduction](#introduction)
2. [Architecture du Projet](#architecture-du-projet)
3. [Installation](#installation)
4. [Utilisation](#utilisation)
5. [Architecture Technique](#architecture-technique)
6. [Plugins Detailles](#plugins-detailles)
7. [API REST](#api-rest)
8. [Base de Donnees](#base-de-donnees)
9. [Configuration](#configuration)
10. [Developpement](#developpement)
11. [Troubleshooting](#troubleshooting)

---

## Introduction

NetScope est un framework modulaire de scan reseau developpe en Python. Il combine plusieurs techniques de scanning (TCP, UDP, banner grabbing) avec des algorithmes de machine learning pour detecter et analyser les services reseau.

### Objectifs du Projet

- Scanner des reseaux pour identifier les hotes et services actifs
- Recuperer les bannieres des services pour identifier les versions
- Detecter les anomalies et vulnerabilites potentielles
- Fournir un score de securite base sur l'analyse ML
- Offrir une interface web intuitive et une CLI puissante

### Caracteristiques Principales

- Architecture modulaire : Systeme de plugins extensible
- Trois modes de scan : Quick, Deep, Custom
- Support multi-protocoles : TCP, UDP, HTTPS/SSL
- Banner grabbing avance : Techniques multiples inspirees de Nmap
- Machine Learning : Classification des services et detection d'anomalies
- Interface web : Dashboard moderne avec Flask
- Base de donnees : Historique et statistiques SQLite
- Support DNS : Scan par nom de domaine ou IP

---

## Architecture du Projet

### Structure des Fichiers

```
netscope/
├── main.py                     # Point d'entree CLI
├── quickstart.sh               # Menu interactif
├── requirements.txt            # Dependances Python
├── README.md                   # Ce fichier
│
├── config/                     # Configuration
│   └── settings.py            # Parametres globaux
│
├── core/                       # Moteur principal
│   ├── engine.py              # Orchestration des scans
│   ├── plugin_manager.py     # Gestion des plugins
│   └── utils.py               # Utilitaires (IP parsing, etc.)
│
├── plugins/                    # Plugins de scan
│   ├── tcp_syn_scanner.py     # Scanner TCP SYN
│   ├── udp_scanner.py         # Scanner UDP
│   ├── banner_grabber.py      # Banner grabbing avance
│   └── service_detector.py    # Detection ML
│
├── storage/                    # Persistance
│   ├── database.py            # Gestionnaire SQLite
│   └── netscope.db            # Base de donnees (creee auto)
│
├── web/                        # Interface web
│   ├── dashboard.py           # API Flask
│   └── templates/
│       └── index.html         # Frontend
│
├── tests/                      # Tests
│   └── test_lab.py            # Environnement de simulation
│
└── docs/                       # Documentation additionnelle
```

---

## Installation

### Prerequis

- Python 3.8 ou superieur
- pip (gestionnaire de packages Python)
- Systeme d'exploitation : Linux, macOS, Windows (WSL recommande)

### Installation Standard

```bash
# 1. Cloner ou extraire le projet
cd ~/Telechargements/netscope

# 2. Creer un environnement virtuel (recommande)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS

# 3. Installer les dependances
pip install -r requirements.txt

# 4. Verifier l'installation
python3 main.py --version
```

---

## Utilisation

### 1. Interface en Ligne de Commande (CLI)

#### Quick Scan (Rapide)

Scan rapide des ports communs avec banner grabbing basique.

```bash
python3 main.py -t 192.168.1.1 --quick
```

Details :
- Duree : 5-10 secondes
- Ports : 17 ports communs
- Plugins : TCP_SYN + BANNER_GRABBER
- Usage : Decouverte rapide

#### Deep Scan (Complet)

Scan approfondi avec toutes les techniques.

```bash
python3 main.py -t 192.168.1.1 --deep
```

Details :
- Duree : 30-60 secondes
- Ports : 17 TCP + 11 UDP
- Plugins : TCP_SYN + UDP_SCANNER + BANNER_GRABBER + SERVICE_DETECTOR
- Usage : Analyse complete avec score de securite

#### Custom Scan (Personnalise)

Scan de ports specifiques.

```bash
python3 main.py -t 192.168.1.1 -p 80,443,3306
```

Details :
- Duree : Variable
- Ports : Ceux specifies
- Plugins : TCP_SYN + BANNER_GRABBER
- Usage : Cibler des ports precis

#### Scan par Nom de Domaine

Support de la resolution DNS.

```bash
python3 main.py -t google.com --quick
```

Le systeme resout automatiquement le domaine en IP.

#### Export des Resultats

Exporter en JSON pour traitement ulterieur.

```bash
python3 main.py -t 192.168.1.1 --deep --export results.json
```

#### Historique

Afficher les scans precedents.

```bash
python3 main.py --history
```

### 2. Interface Web (Dashboard)

#### Lancement

```bash
python3 main.py --web
```

Ouvrir un navigateur a l'adresse : http://localhost:5000

#### Fonctionnalites du Dashboard

1. Statistiques Globales
   - Nombre total de scans
   - Hotes scannes
   - Ports ouverts detectes
   - Alertes actives

2. Lancement de Scan
   - Saisie d'IP ou nom de domaine
   - Choix du type de scan (Quick/Deep/Custom)
   - Specification de ports optionnels

3. Affichage des Resultats
   - Score de securite (0-100) avec code couleur
   - Liste des ports ouverts (TCP et UDP)
   - Bannieres completes avec bouton "Voir plus"
   - Informations SSL/TLS pour HTTPS
   - Headers HTTP revelateurs
   - Niveau de confiance par service
   - Anomalies detectees
   - Vulnerabilites potentielles

---

## Architecture Technique

### 1. Moteur Principal (core/engine.py)

Classe : ScanEngine

Responsable de l'orchestration de tous les scans.

Methodes Principales

resolve_domain(target)
Resout un nom de domaine en IP
Retourne : (ip, hostname, is_domain)

quick_scan(target, ports)
Scan rapide : TCP_SYN + BANNER_GRABBER
Duree : environ 5-10s

deep_scan(target, ports)
Scan complet : TCP + UDP + BANNER + ML
Duree : environ 30-60s

scan_target(target, scan_types, ports)
Methode generique de scan

Processus :
1. Resolution DNS si necessaire
2. Creation de session de scan
3. Parse de la range d'IPs
4. Execution sequentielle des plugins
5. Calcul de la duree
6. Sauvegarde en base de donnees

### 2. Gestionnaire de Plugins (core/plugin_manager.py)

Classe : PluginBase (Abstraite)

Classe de base pour tous les plugins.

Tous les plugins doivent implementer :
- run(target, **kwargs) : Methode principale
- get_info() : Retourne les informations du plugin

Classe : PluginManager

Charge et gere tous les plugins disponibles.

Methodes :
- load_plugins() : Charge dynamiquement tous les fichiers .py du dossier plugins/
- get_plugin(name) : Recupere un plugin par son nom
- run_plugin(name, target, **kwargs) : Execute un plugin specifique

### 3. Utilitaires (core/utils.py)

Fonctions utilitaires pour le parsing et validation.

validate_ip(ip)
Valide une adresse IP
Utilise ipaddress.ip_address() de la stdlib

parse_ip_range(ip_range)
Parse un range d'IPs

Exemples :
- "192.168.1.1" -> ["192.168.1.1"]
- "192.168.1.0/24" -> ["192.168.1.1", "192.168.1.2", ..., "192.168.1.254"]

parse_port_range(port_range)
Parse une specification de ports

Exemples :
- "80" -> [80]
- "80,443" -> [80, 443]
- "8000-8005" -> [8000, 8001, 8002, 8003, 8004, 8005]

calculate_scan_duration(start_time, end_time)
Calcule et formate la duree d'un scan
Retourne : "5.23s" ou "1m 23.45s"

---

## Plugins Detailles

### 1. TCP SYN Scanner (tcp_syn_scanner.py)

Classe : TCPSYNScanner

Scanne les ports TCP pour detecter les ports ouverts.

Fonctionnement :
1. Utilise TCP Connect scan (pas besoin de privileges root)
2. socket.connect_ex() pour tester chaque port
3. Multithreading avec ThreadPoolExecutor
4. Timeout configurable par port

Methode scan_port
Teste un port specifique

Etats possibles :
- open : Port repond (connect_ex == 0)
- closed : Port refuse la connexion (connect_ex == 111)
- filtered : Timeout ou autre erreur
- error : Erreur technique

Services Communs
Dictionnaire de mapping port -> service

### 2. UDP Scanner (udp_scanner.py)

Classe : UDPScanner

Detecte les services UDP.

Fonctionnement :
1. Envoie un paquet UDP vide
2. Attend une reponse ou ICMP Port Unreachable
3. Timeout plus long que TCP (2s par defaut)

Limites
UDP est un protocole sans connexion :
- Pas de reponse ne signifie pas forcement "ferme"
- Etat "open|filtered" signifie "probablement ouvert"
- Moins fiable que TCP

### 3. Banner Grabber (banner_grabber.py)

Classe : AdvancedBannerGrabber

Recupere les bannieres des services avec techniques avancees.

Techniques Utilisees :

1. Probes Multiples HTTP
Envoie 5 requetes HTTP differentes :
- Requete normale GET
- OPTIONS (revele methodes supportees)
- HEAD (leger)
- Requete invalide (provoque erreur)
- HTTP/1.0 (ancien)

2. Extraction Headers HTTP
Recherche des headers revelateurs :
- Server: Version du serveur web
- X-Powered-By: Technologie backend
- X-AspNet-Version: Version ASP.NET
- Via: Proxies intermediaires
- X-Backend-Server: Serveur backend

3. Inspection SSL/TLS
Pour les ports HTTPS (443, 8443)
Recupere les informations du certificat SSL

Retourne :
- common_name: Nom commun (CN)
- organization: Organisation
- issuer: Emetteur du certificat
- not_before: Date de debut de validite
- not_after: Date d'expiration
- tls_version: Version TLS negociee

4. Fingerprinting par Comportement
Analyse les patterns d'erreur pour deviner le serveur

Patterns :
- Apache: "400 Bad Request" avec texte specifique
- nginx: "<hr><center>nginx</center>"
- IIS: Messages contenant "Microsoft" ou "IIS"

Methode analyze_banner_advanced
Synthetise toutes les informations collectees

Priorite :
1. Headers HTTP directs
2. Bannieres des probes
3. Informations SSL
4. Fingerprinting comportemental

Retourne :
- service: Nom du service
- version: Version detectee
- confidence: high/medium/low
- collection_method: Liste des methodes utilisees

### 4. Service Detector (service_detector.py)

Classe : ServiceDetector

Detection intelligente avec machine learning simple.

Technique : Pattern Matching
Utilise une base de patterns pour classifier

Methode classify_service
Classification en 3 etapes :
1. Pattern matching avec SERVICE_PATTERNS
2. Scoring : nombre de patterns matches / total patterns
3. Fallback sur le port si aucun match

Detection d'Anomalies
Detecte 2 types d'anomalies :
1. Services sur ports non-standards
2. Multiples instances d'un meme service

Score de Securite
Calcul du score (base 100)

Penalites :
- Ports a haut risque ouverts : -15 par port
- Vulnerabilites detectees : -10 par vulnerabilite
- Services non identifies : -5 par service

Niveaux :
- GOOD : 80-100 (vert)
- MEDIUM : 60-79 (orange)
- LOW : 0-59 (rouge)

---

## API REST

Le dashboard web expose une API REST complete.

### Endpoints Disponibles

#### GET /
Page principale du dashboard

#### POST /api/scan
Lance un scan

Body JSON :
{
  "target": "192.168.1.1",
  "scan_type": "quick",
  "ports": "80,443"
}

Parametres :
- target (requis) : IP ou nom de domaine
- scan_type : "quick", "deep", ou "custom"
- ports (optionnel) : Ports a scanner

#### GET /api/scans
Liste tous les scans

Query params :
- limit : Nombre max de scans (defaut: 10)

#### GET /api/scan/:scan_id
Recupere un scan specifique

#### GET /api/host/:ip
Historique d'un hote

#### GET /api/statistics
Statistiques globales

#### GET /api/plugins
Liste les plugins disponibles

#### POST /api/compare
Compare deux scans

---

## Base de Donnees

### Schema SQLite

Table : scans
Stocke les metadonnees de chaque scan

Table : hosts
Hotes decouverts

Table : ports
Ports detectes

Table : vulnerabilities
Vulnerabilites detectees

Table : alerts
Alertes systeme

Classe DatabaseManager
Gestion de toutes les operations base de donnees

save_scan(scan_data)
Sauvegarde un scan complet

Operations :
1. Insert dans table scans
2. Insert hotes dans table hosts
3. Insert ports dans table ports
4. Transaction atomique

get_statistics()
Calcule les statistiques en temps reel

Requetes SQL :
- COUNT(*) sur scans
- COUNT(DISTINCT ip) sur hosts
- COUNT(*) WHERE state='open' sur ports
- COUNT(*) WHERE read=0 sur alerts

---

## Configuration

### Fichier config/settings.py

Configuration centralisee du framework.

VERSION = "1.0.0"

SCAN_CONFIG = {
    'timeout': 3.0,           # Timeout par port (secondes)
    'max_threads': 50,        # Threads paralleles max
    'max_retries': 2,         # Tentatives par port
    'delay_between_scans': 0.01  # Delai entre scans (secondes)
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
    3306, 3389, 5432, 5900, 8080, 8443, 27017
]

WEB_CONFIG = {
    'host': '0.0.0.0',
    'port': 5000,
    'debug': False
}

SECURITY_THRESHOLDS = {
    'high_risk_ports': [23, 445, 3389],
    'outdated_versions': ['Apache/2.2', 'OpenSSH_5'],
    'suspicious_banners': ['default', 'test', 'admin']
}

### Personnalisation

Pour modifier les parametres :
1. Editer config/settings.py
2. Ajouter des ports a COMMON_PORTS
3. Ajuster timeout et max_threads selon performances
4. Ajouter des patterns a SERVICE_PATTERNS

---

## Developpement

### Ajouter un Nouveau Plugin

1. Creer plugins/mon_plugin.py

2. Heriter de PluginBase

3. Le plugin sera charge automatiquement au demarrage

### Tests

Environnement de Test
Simulateur de services pour tests :

python3 tests/test_lab.py

Simule :
- Port 2222 : SSH (OpenSSH 8.0)
- Port 8080 : HTTP (nginx 1.18.0)
- Port 3307 : MySQL (5.7.32)

Scanner l'Environnement de Test

Terminal 1 :
python3 tests/test_lab.py

Terminal 2 :
python3 main.py -t 127.0.0.1 --deep

---

## Troubleshooting

### Probleme : "No module named 'flask'"

Solution :
pip install flask

### Probleme : "Permission denied" sur ports < 1024

Cause : Les ports < 1024 necessitent les privileges root

Solution : Utiliser le port 5000 (par defaut) ou sudo

### Probleme : UDP scan ne retourne rien

Cause : UDP est un protocole sans connexion, difficile a scanner

Solution : 
- Augmenter le timeout dans config/settings.py
- UDP scan est moins fiable que TCP

### Probleme : Bannieres "N/A" sur serveurs reels

Cause : Les serveurs modernes masquent souvent leurs bannieres

Solution : 
- C'est normal, pas un bug
- Le plugin avance utilise plusieurs techniques
- Certains serveurs ne revelent aucune information

### Probleme : Base de donnees verrouillee

Cause : Deux processus accedent simultanement a la BDD

Solution :
rm storage/netscope.db
# Relancer le programme pour recreer la BDD

### Probleme : Erreur "calculate_scan_duration"

Solution : Verifier que core/utils.py contient la bonne fonction

---

## Licence

Ce projet est a but educatif uniquement.

AVERTISSEMENT :
Ne scanner que des reseaux dont vous avez l'autorisation. 
Le scanning non autorise peut etre illegal dans votre juridiction.

---

Version : 1.0.0
Derniere mise a jour : Fevrier 2024
