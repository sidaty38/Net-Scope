"""
Gestionnaire de plugins pour NetScope
Architecture modulaire permettant l'ajout facile de nouveaux scanners
"""
import importlib
import inspect
import os
from typing import Dict, List, Any
from abc import ABC, abstractmethod

class PluginBase(ABC):
    """Classe de base pour tous les plugins"""
    
    def __init__(self):
        self.name = "BasePlugin"
        self.description = "Plugin de base"
        self.version = "1.0"
        self.enabled = True
    
    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Méthode principale du plugin
        
        Args:
            target: Cible du scan (IP ou range)
            **kwargs: Arguments supplémentaires
            
        Returns:
            Dictionnaire avec les résultats du scan
        """
        pass
    
    @abstractmethod
    def get_info(self) -> Dict[str, str]:
        """Retourne les informations du plugin"""
        pass
    
    def validate_input(self, target: str) -> bool:
        """Valide l'entrée du plugin"""
        return True

class PluginManager:
    """Gestionnaire de plugins"""
    
    def __init__(self, plugin_directory: str = "plugins"):
        self.plugin_directory = plugin_directory
        self.plugins: Dict[str, PluginBase] = {}
        self.load_plugins()
    
    def load_plugins(self):
        """Charge tous les plugins disponibles"""
        plugin_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), self.plugin_directory)
        
        if not os.path.exists(plugin_path):
            print(f"[!] Répertoire des plugins introuvable: {plugin_path}")
            return
        
        for filename in os.listdir(plugin_path):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]
                try:
                    # Import dynamique du module
                    module = importlib.import_module(f"plugins.{module_name}")
                    
                    # Recherche des classes héritant de PluginBase
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, PluginBase) and obj is not PluginBase:
                            plugin_instance = obj()
                            self.plugins[plugin_instance.name] = plugin_instance
                            print(f"[+] Plugin chargé: {plugin_instance.name}")
                
                except Exception as e:
                    print(f"[!] Erreur lors du chargement du plugin {module_name}: {e}")
    
    def get_plugin(self, name: str) -> PluginBase:
        """Récupère un plugin par son nom"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, str]]:
        """Liste tous les plugins disponibles"""
        return [plugin.get_info() for plugin in self.plugins.values()]
    
    def run_plugin(self, name: str, target: str, **kwargs) -> Dict[str, Any]:
        """Exécute un plugin spécifique"""
        plugin = self.get_plugin(name)
        if not plugin:
            return {"error": f"Plugin '{name}' introuvable"}
        
        if not plugin.enabled:
            return {"error": f"Plugin '{name}' désactivé"}
        
        if not plugin.validate_input(target):
            return {"error": f"Entrée invalide pour le plugin '{name}'"}
        
        try:
            return plugin.run(target, **kwargs)
        except Exception as e:
            return {"error": f"Erreur lors de l'exécution du plugin '{name}': {str(e)}"}
    
    def enable_plugin(self, name: str):
        """Active un plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = True
            return True
        return False
    
    def disable_plugin(self, name: str):
        """Désactive un plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = False
            return True
        return False
