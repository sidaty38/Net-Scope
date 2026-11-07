#!/bin/bash

# NetScope - Script de Demarrage Rapide
# Version 2.1 - Custom Scan CORRIGE

clear

print_header() {
    echo "============================================================"
    echo "          NetScope - Network Security Scanner"
    echo "============================================================"
    echo ""
}

show_menu() {
    clear
    print_header
    echo "Menu Principal"
    echo ""
    echo "  [1] Quick Scan (Rapide - 5-10s)"
    echo "  [2] Deep Scan (Complet - 30-60s)"
    echo "  [3] Custom Scan (Personnalise)"
    echo "  [4] Dashboard Web"
    echo "  [5] Historique des scans"
    echo "  [6] Statistiques"
    echo "  [7] Plugins disponibles"
    echo "  [8] Installation dependances"
    echo "  [0] Quitter"
    echo ""
    echo "------------------------------------------------------------"
}

quick_scan() {
    clear
    print_header
    echo "Quick Scan"
    echo "------------------------------------------------------------"
    echo ""
    read -p "Entrez la cible (IP ou domaine, ex: 192.168.1.1 ou google.com): " target
    
    if [ -z "$target" ]; then
        echo "Erreur: Cible requise"
        read -p "Appuyez sur Entree pour continuer..."
        return
    fi
    
    echo ""
    echo "Lancement du scan rapide sur $target..."
    echo ""
    python3 main.py -t "$target" --quick
    
    echo ""
    echo "Scan termine"
    read -p "Appuyez sur Entree pour continuer..."
}

deep_scan() {
    clear
    print_header
    echo "Deep Scan"
    echo "------------------------------------------------------------"
    echo ""
    read -p "Entrez la cible (IP ou domaine, ex: 192.168.1.1 ou example.com): " target
    
    if [ -z "$target" ]; then
        echo "Erreur: Cible requise"
        read -p "Appuyez sur Entree pour continuer..."
        return
    fi
    
    echo ""
    echo "Lancement du scan complet sur $target..."
    echo "Cela peut prendre 30-60 secondes..."
    echo ""
    python3 main.py -t "$target" --deep
    
    echo ""
    echo "Scan termine"
    read -p "Appuyez sur Entree pour continuer..."
}

custom_scan() {
    clear
    print_header
    echo "Custom Scan"
    echo "------------------------------------------------------------"
    echo ""
    read -p "Entrez la cible (IP ou domaine, ex: 192.168.1.1 ou example.com): " target
    read -p "Entrez les ports (ex: 80,443,3306 ou 8000-8100): " ports
    
    if [ -z "$target" ]; then
        echo "Erreur: Cible requise"
        read -p "Appuyez sur Entree pour continuer..."
        return
    fi
    
    if [ -z "$ports" ]; then
        echo "Erreur: Ports requis pour un scan personnalise"
        echo "Pour scanner tous les ports communs, utilisez Quick Scan"
        read -p "Appuyez sur Entree pour continuer..."
        return
    fi
    
    echo ""
    echo "Lancement du scan personnalise sur $target..."
    echo "Ports cibles: $ports"
    echo ""
    
    # CORRECTION : Ajouter --scan-types pour forcer custom scan
    python3 main.py -t "$target" -p "$ports" --scan-types TCP_SYN BANNER_GRABBER
    
    echo ""
    echo "Scan termine"
    read -p "Appuyez sur Entree pour continuer..."
}

start_dashboard() {
    clear
    print_header
    echo "Dashboard Web"
    echo "------------------------------------------------------------"
    echo ""
    echo "Lancement du dashboard..."
    echo "URL: http://localhost:5000"
    echo ""
    echo "Appuyez sur Ctrl+C pour arreter"
    echo ""
    python3 main.py --web
}

show_history() {
    clear
    print_header
    echo "Historique des Scans"
    echo "------------------------------------------------------------"
    echo ""
    python3 main.py --history
    echo ""
    read -p "Appuyez sur Entree pour continuer..."
}

show_statistics() {
    clear
    print_header
    echo "Statistiques"
    echo "------------------------------------------------------------"
    echo ""
    
    if [ -f "storage/netscope.db" ]; then
        echo "Base de donnees trouvee"
        echo ""
        python3 << 'PYEOF'
from storage.database import DatabaseManager
db = DatabaseManager()
stats = db.get_statistics()
print(f"Scans totaux: {stats.get('total_scans', 0)}")
print(f"Hotes scannes: {stats.get('total_hosts', 0)}")
print(f"Ports ouverts: {stats.get('total_open_ports', 0)}")
print(f"Alertes: {stats.get('unread_alerts', 0)}")
PYEOF
    else
        echo "Aucune base de donnees trouvee"
    fi
    
    echo ""
    read -p "Appuyez sur Entree pour continuer..."
}

list_plugins() {
    clear
    print_header
    echo "Plugins Disponibles"
    echo "------------------------------------------------------------"
    echo ""
    python3 main.py --list-plugins
    echo ""
    read -p "Appuyez sur Entree pour continuer..."
}

install_deps() {
    clear
    print_header
    echo "Installation des Dependances"
    echo "------------------------------------------------------------"
    echo ""
    
    if [ ! -f "requirements.txt" ]; then
        echo "Erreur: requirements.txt non trouve"
        read -p "Appuyez sur Entree pour continuer..."
        return
    fi
    
    echo "Verification de Python..."
    if command -v python3 &> /dev/null; then
        echo "Python3 installe: $(python3 --version)"
    else
        echo "Erreur: Python3 non installe"
        read -p "Appuyez sur Entree pour continuer..."
        return
    fi
    
    echo ""
    echo "Installation des packages Python..."
    pip3 install -r requirements.txt
    
    echo ""
    echo "Installation terminee"
    read -p "Appuyez sur Entree pour continuer..."
}

# Boucle principale
while true; do
    show_menu
    read -p "Votre choix [0-8]: " choice
    
    case $choice in
        1) quick_scan ;;
        2) deep_scan ;;
        3) custom_scan ;;
        4) start_dashboard ;;
        5) show_history ;;
        6) show_statistics ;;
        7) list_plugins ;;
        8) install_deps ;;
        0)
            clear
            echo ""
            echo "Merci d'avoir utilise NetScope"
            echo ""
            exit 0
            ;;
        *)
            echo ""
            echo "Choix invalide"
            sleep 1
            ;;
    esac
done
