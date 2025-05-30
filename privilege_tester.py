#!/usr/bin/env python3
"""
Diagnostic et test des privilèges pour DHCP Monitor
Résout automatiquement les problèmes de permissions
"""

import os
import sys
import platform
import subprocess
import socket
import pwd
import grp
from pathlib import Path

class PrivilegeTester:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.fixes = []
        
    def print_header(self, text):
        print(f"\n{'='*60}")
        print(f"🔍 {text}")
        print('='*60)
        
    def print_status(self, message, status="INFO"):
        icons = {"INFO": "ℹ️", "OK": "✅", "WARNING": "⚠️", "ERROR": "❌", "FIX": "🔧"}
        print(f"{icons.get(status, 'ℹ️')} {message}")
        
    def run_command(self, cmd, capture_output=True):
        """Exécuter une commande système de manière sécurisée"""
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            result = subprocess.run(cmd, capture_output=capture_output, text=True, timeout=10)
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
            
    def check_system_info(self):
        """Vérifier les informations système"""
        self.print_header("INFORMATIONS SYSTÈME")
        
        # OS et version
        os_info = f"{platform.system()} {platform.release()}"
        self.print_status(f"Système: {os_info}")
        
        # Architecture
        self.print_status(f"Architecture: {platform.machine()}")
        
        # Utilisateur actuel
        try:
            current_user = pwd.getpwuid(os.getuid()).pw_name
            self.print_status(f"Utilisateur: {current_user}")
        except:
            self.print_status("Utilisateur: Inconnu")
            
        # Groupes
        try:
            groups = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]
            self.print_status(f"Groupes: {', '.join(groups)}")
        except:
            self.print_status("Groupes: Impossible à déterminer")
            
    def check_display(self):
        """Vérifier la configuration de l'affichage"""
        self.print_header("CONFIGURATION AFFICHAGE")
        
        display = os.environ.get('DISPLAY')
        if display:
            self.print_status(f"DISPLAY: {display}", "OK")
        else:
            self.print_status("DISPLAY non configuré", "WARNING")
            self.warnings.append("Variable DISPLAY manquante")
            self.fixes.append("export DISPLAY=:0")
            
        # Vérifier les sockets X11
        x11_sockets = list(Path('/tmp/.X11-unix').glob('X*')) if Path('/tmp/.X11-unix').exists() else []
        if x11_sockets:
            self.print_status(f"Sockets X11 trouvés: {len(x11_sockets)}", "OK")
            for socket_path in x11_sockets:
                display_num = socket_path.name[1:]  # Enlever le 'X'
                self.print_status(f"  - :{display_num}")
        else:
            self.print_status("Aucun socket X11 trouvé", "WARNING")
            
    def check_privileges(self):
        """Vérifier les privilèges"""
        self.print_header("PRIVILÈGES SYSTÈME")
        
        # Root/sudo
        if os.geteuid() == 0:
            self.print_status("Exécution en tant que root", "OK")
        else:
            self.print_status("Pas de privilèges root", "WARNING")
            self.warnings.append("Privilèges root requis pour la capture réseau")
            
        # Test sudo
        success, stdout, stderr = self.run_command("sudo -n whoami")
        if success:
            self.print_status("sudo disponible sans mot de passe", "OK")
        else:
            self.print_status("sudo nécessite un mot de passe", "WARNING")
            
    def check_raw_sockets(self):
        """Tester l'accès aux raw sockets"""
        self.print_header("ACCÈS RAW SOCKETS")
        
        try:
            # Test de création d'un raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            self.print_status("Raw sockets accessible", "OK")
            return True
        except PermissionError:
            self.print_status("Raw sockets inaccessible - Permission refusée", "ERROR")
            self.errors.append("Accès raw sockets refusé")
            return False
        except Exception as e:
            self.print_status(f"Test raw sockets échoué: {e}", "WARNING")
            return False
            
    def check_setcap(self):
        """Vérifier et configurer setcap"""
        self.print_header("CONFIGURATION SETCAP")
        
        # Vérifier si setcap est installé
        success, _, _ = self.run_command("which setcap")
        if not success:
            self.print_status("setcap non installé", "ERROR")
            self.errors.append("setcap manquant")
            self.fixes.append("sudo apt install libcap2-bin")
            return False
            
        # Chemin Python
        python_path = sys.executable
        self.print_status(f"Python path: {python_path}")
        
        # Vérifier les capacités actuelles
        success, stdout, _ = self.run_command(f"getcap {python_path}")
        if success and "cap_net_raw" in stdout:
            self.print_status("Capacités réseau configurées", "OK")
            return True
        else:
            self.print_status("Capacités réseau non configurées", "WARNING")
            
            # Tenter de configurer setcap
            self.print_status("Tentative de configuration setcap...", "FIX")
            cmd = f"sudo setcap cap_net_raw,cap_net_admin=eip {python_path}"
            success, stdout, stderr = self.run_command(cmd)
            
            if success:
                self.print_status("setcap configuré avec succès", "OK")
                return True
            else:
                self.print_status(f"Échec setcap: {stderr}", "ERROR")
                self.errors.append(f"setcap échoué: {stderr}")
                
                # Suggestion alternative
                self.fixes.append("Alternative: utiliser sudo pour lancer l'application")
                return False
                
    def check_python_deps(self):
        """Vérifier les dépendances Python"""
        self.print_header("DÉPENDANCES PYTHON")
        
        # Vérifier Scapy
        try:
            import scapy
            from scapy.all import get_if_list
            interfaces = get_if_list()
            self.print_status(f"Scapy OK - {len(interfaces)} interfaces", "OK")
        except ImportError:
            self.print_status("Scapy non installé", "ERROR")
            self.errors.append("Scapy manquant")
            self.fixes.append("pip3 install --user scapy")
        except Exception as e:
            self.print_status(f"Erreur Scapy: {e}", "WARNING")
            
        # Vérifier tkinter
        try:
            import tkinter
            self.print_status("Tkinter disponible", "OK")
        except ImportError:
            self.print_status("Tkinter non installé", "ERROR")
            self.errors.append("Tkinter manquant")
            self.fixes.append("sudo apt install python3-tkinter")
            
    def check_network_interfaces(self):
        """Vérifier les interfaces réseau"""
        self.print_header("INTERFACES RÉSEAU")
        
        try:
            import scapy.all as scapy
            interfaces = scapy.get_if_list()
            
            self.print_status(f"Interfaces détectées: {len(interfaces)}")
            for iface in interfaces:
                self.print_status(f"  - {iface}")
                
            # Vérifier les permissions sur les interfaces
            for iface in interfaces[:3]:  # Tester les 3 premières
                try:
                    # Test de sniffing rapide
                    scapy.sniff(iface=iface, count=1, timeout=1, store=False)
                    self.print_status(f"Interface {iface}: Accessible", "OK")
                except Exception as e:
                    self.print_status(f"Interface {iface}: Erreur - {str(e)[:50]}", "WARNING")
                    
        except ImportError:
            self.print_status("Impossible de tester - Scapy manquant", "ERROR")
        except Exception as e:
            self.print_status(f"Erreur lors du test: {e}", "ERROR")
            
    def create_launch_scripts(self):
        """Créer des scripts de lancement"""
        self.print_header("CRÉATION SCRIPTS DE LANCEMENT")
        
        scripts = {
            "launch_with_sudo.sh": """#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec sudo..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
sudo -E python3 monitor.py
""",
            "launch_with_setcap.sh": """#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec setcap..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
python3 monitor.py
""",
            "fix_permissions.sh": """#!/bin/bash
echo "🔧 Configuration des permissions..."
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
echo "✅ Permissions configurées!"
"""
        }
        
        for script_name, content in scripts.items():
            try:
                with open(script_name, 'w') as f:
                    f.write(content)
                os.chmod(script_name, 0o755)
                self.print_status(f"Créé: {script_name}", "OK")
            except Exception as e:
                self.print_status(f"Erreur création {script_name}: {e}", "ERROR")
                
    def generate_report(self):
        """Générer un rapport de diagnostic"""
        self.print_header("RAPPORT DE DIAGNOSTIC")
        
        if not self.errors and not self.warnings:
            self.print_status("Configuration OK - Aucun problème détecté", "OK")
            return
            
        if self.errors:
            self.print_status("Erreurs critiques:", "ERROR")
            for error in self.errors:
                self.print_status(f"  • {error}", "ERROR")
                
        if self.warnings:
            self.print_status("Avertissements:", "WARNING")
            for warning in self.warnings:
                self.print_status(f"  • {warning}", "WARNING")
                
        if self.fixes:
            self.print_status("Solutions recommandées:", "FIX")
            for i, fix in enumerate(self.fixes, 1):
                self.print_status(f"  {i}. {fix}", "FIX")
                
    def run_full_diagnostic(self):
        """Exécuter le diagnostic complet"""
        print("🔍 DIAGNOSTIC COMPLET DHCP MONITOR")
        print("="*60)
        
        self.check_system_info()
        self.check_display()
        self.check_privileges()
        self.check_python_deps()
        self.check_raw_sockets()
        self.check_setcap()
        self.check_network_interfaces()
        self.create_launch_scripts()
        self.generate_report()
        
        print(f"\n{'='*60}")
        print("🎯 MÉTHODES DE LANCEMENT RECOMMANDÉES")
        print('='*60)
        print("1. sudo python3 monitor.py")
        print("2. ./launch_with_sudo.sh")
        print("3. ./fix_permissions.sh && ./launch_with_setcap.sh")
        print("\n💡 Pour SSH avec X11: ssh -X user@host")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--fix":
        print("🔧 Mode correction automatique activé")
        
    tester = PrivilegeTester()
    tester.run_full_diagnostic()

if __name__ == "__main__":
    main()
