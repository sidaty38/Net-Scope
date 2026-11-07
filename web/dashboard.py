"""
API REST et Dashboard pour NetScope 
Support: Bannières complètes, Noms de domaine, Différenciation scans
"""
from flask import Flask, render_template, jsonify, request
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.engine import ScanEngine
from storage.database import DatabaseManager
from config.settings import WEB_CONFIG

app = Flask(__name__)
engine = ScanEngine()
db = DatabaseManager()

@app.route('/')
def index():
    """Page principale"""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    """
    Lance un scan - SUPPORT DOMAINE AJOUTÉ
    
    Body JSON:
    {
        "target": "192.168.1.1" ou "google.com",
        "scan_type": "quick|deep|custom",
        "ports": "80,443,8000-9000" (optionnel)
    }
    """
    data = request.json
    
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    ports_str = data.get('ports', '')
    
    if not target:
        return jsonify({'error': 'Cible requise'}), 400
    
    # Parse ports si fournis
    ports = None
    if ports_str:
        from core.utils import parse_port_range
        try:
            ports = parse_port_range(ports_str)
        except ValueError as e:
            return jsonify({'error': f'Ports invalides: {e}'}), 400
    
    # Lancer le scan approprié
    try:
        if scan_type == 'quick':
            results = engine.quick_scan(target, ports)
        elif scan_type == 'deep':
            results = engine.deep_scan(target, ports)
        elif scan_type == 'custom':
            # Pour custom, on utilise TCP + BANNER par défaut
            scan_types = data.get('scan_types', ['TCP_SYN', 'BANNER_GRABBER'])
            results = engine.custom_scan(target, scan_types, ports)
        else:
            return jsonify({'error': 'Type de scan invalide'}), 400
        
        # Sauvegarder dans la base de données
        if 'error' not in results:
            db.save_scan(results)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Liste tous les scans"""
    limit = request.args.get('limit', 10, type=int)
    scans = db.get_all_scans(limit)
    return jsonify(scans)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Récupère un scan spécifique"""
    scan = db.get_scan(scan_id)
    if scan:
        return jsonify(scan)
    return jsonify({'error': 'Scan non trouvé'}), 404

@app.route('/api/host/<ip>', methods=['GET'])
def get_host(ip):
    """Récupère l'historique d'un hôte"""
    history = db.get_host_history(ip)
    return jsonify(history)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Récupère les alertes"""
    alerts = db.get_unread_alerts()
    return jsonify(alerts)

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Récupère les statistiques globales"""
    stats = db.get_statistics()
    return jsonify(stats)

@app.route('/api/plugins', methods=['GET'])
def get_plugins():
    """Liste les plugins disponibles"""
    plugins = engine.plugin_manager.list_plugins()
    return jsonify(plugins)

@app.route('/api/compare', methods=['POST'])
def compare_scans():
    """Compare deux scans"""
    data = request.json
    scan_id1 = data.get('scan_id1')
    scan_id2 = data.get('scan_id2')
    
    if not scan_id1 or not scan_id2:
        return jsonify({'error': 'Deux scan_id requis'}), 400
    
    comparison = engine.compare_scans(scan_id1, scan_id2)
    return jsonify(comparison)

def run_dashboard():
    """Lance le dashboard web"""
    host = WEB_CONFIG.get('host', '0.0.0.0')
    port = WEB_CONFIG.get('port', 5000)
    
    print("""
╔════════════════════════════════════════════════════════════╗
║              NetScope Dashboard Started                    ║
╚════════════════════════════════════════════════════════════╝

    🌐 URL: http://{}:{}
    
    📝 Features:
       • Quick Scan ⚡ (Rapide, ports communs)
       • Deep Scan 🔍 (Complet, toutes techniques)
       • Custom Scan 🎨 (Personnalisé, vos choix)
       • Support IP et Noms de domaine 🌐
       • Bannières complètes 📄
    
    ⚡ Quick: TCP + Banner (5-10s)
    🔍 Deep: TCP + UDP + Banner + ML + Sécu (30-60s)
    🎨 Custom: Vous choisissez
    
    Ctrl+C pour arrêter
    
═══════════════════════════════════════════════════════════════
    """.format(host, port))
    
    app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    run_dashboard()
