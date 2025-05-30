#!/usr/bin/env python3
"""
DHCP Monitor GUI - Version avec gestion avancée des permissions
Surveillance DHCP avec interface graphique moderne et gestion des privilèges
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import re
import subprocess
import sys
import os
import platform
from datetime import datetime

# Import conditionnel de Scapy avec gestion d'erreur
try:
    from scapy.all import sniff, DHCP, IP, Ether, UDP, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PermissionManager:
    """Gestionnaire de permissions pour la capture réseau"""
    
    @staticmethod
    def is_admin():
        """Vérifier si l'application s'exécute avec des privilèges administrateur"""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False
    
    @staticmethod
    def restart_as_admin():
        """Redémarrer l'application avec des privilèges administrateur"""
        try:
            if platform.system() == "Windows":
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
            else:
                # Linux/Mac - utiliser sudo
                subprocess.call(['sudo', sys.executable] + sys.argv)
            sys.exit(0)
        except Exception as e:
            return False, str(e)
        return True, ""
    
    @staticmethod
    def setup_linux_permissions():
        """Configuration des permissions pour Linux"""
        try:
            # Vérifier si setcap est disponible
            result = subprocess.run(['which', 'setcap'], capture_output=True)
            if result.returncode != 0:
                return False, "setcap n'est pas disponible"
            
            # Obtenir le chemin de l'interpréteur Python
            python_path = sys.executable
            
            # Ajouter les capacités CAP_NET_RAW et CAP_NET_ADMIN
            cmd = ['sudo', 'setcap', 'cap_net_raw,cap_net_admin+eip', python_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, "Permissions configurées avec succès"
            else:
                return False, result.stderr
                
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def check_raw_socket_permission():
        """Tester si les raw sockets sont accessibles"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            return True
        except PermissionError:
            return False
        except Exception:
            return True  # Autres erreurs ne sont pas liées aux permissions

class DHCPMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 DHCP Monitor - Option 50 Tracker")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')
        
        # Variables de contrôle
        self.is_monitoring = False
        self.sniff_thread = None
        self.message_queue = queue.Queue()
        self.gateway_ip = tk.StringVar()
        self.selected_interface = tk.StringVar()
        self.permission_manager = PermissionManager()
        
        # Créer l'interface
        self.create_widgets()
        self.setup_styles()
        
        # Vérifier les permissions et Scapy
        self.check_environment()
        
        # Démarrer la vérification de la queue
        self.check_queue()
    
    def check_environment(self):
        """Vérifier l'environnement et les permissions"""
        if not SCAPY_AVAILABLE:
            self.log_message("❌ ERREUR: Scapy n'est pas installé!", "error")
            self.log_message("💡 Installez avec: pip install scapy", "info")
            self.start_button.config(state="disabled")
            return
        
        # Vérifier les permissions
        if not self.permission_manager.is_admin():
            self.log_message("⚠️ ATTENTION: Privilèges administrateur requis", "warning")
            self.show_permission_dialog()
        else:
            self.log_message("✅ Privilèges administrateur détectés", "success")
            self.load_interfaces()
            
            # Test supplémentaire pour les raw sockets
            if not self.permission_manager.check_raw_socket_permission():
                self.log_message("⚠️ Problème d'accès aux raw sockets", "warning")
                if platform.system() == "Linux":
                    self.suggest_linux_setup()
    
    def show_permission_dialog(self):
        """Afficher une boîte de dialogue pour les permissions"""
        system = platform.system()
        
        if system == "Windows":
            msg = """Cette application nécessite des privilèges administrateur pour capturer le trafic réseau.

Options:
1. Redémarrer en tant qu'administrateur (recommandé)
2. Continuer sans privilèges (fonctionnalité limitée)

Souhaitez-vous redémarrer avec des privilèges administrateur?"""
        else:
            msg = """Cette application nécessite des privilèges root pour capturer le trafic réseau.

Options:
1. Redémarrer avec sudo (recommandé)
2. Configurer les permissions avec setcap
3. Continuer sans privilèges (fonctionnalité limitée)

Souhaitez-vous redémarrer avec sudo?"""
        
        result = messagebox.askyesnocancel("Privilèges requis", msg)
        
        if result is True:  # Oui - redémarrer
            success, error = self.permission_manager.restart_as_admin()
            if not success:
                messagebox.showerror("Erreur", f"Impossible de redémarrer: {error}")
        elif result is False and system == "Linux":  # Non sur Linux - proposer setcap
            self.suggest_linux_setup()
        # None = Annuler - continuer sans privilèges
    
    def suggest_linux_setup(self):
        """Proposer la configuration Linux avec setcap"""
        msg = """Alternative pour Linux: Configurer les permissions avec setcap

Cette commande donne les permissions nécessaires à Python:
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3

Souhaitez-vous que l'application tente de configurer cela automatiquement?"""
        
        if messagebox.askyesno("Configuration Linux", msg):
            success, message = self.permission_manager.setup_linux_permissions()
            if success:
                messagebox.showinfo("Succès", message + "\nVeuillez redémarrer l'application.")
            else:
                messagebox.showerror("Erreur", f"Échec de la configuration: {message}")
    
    def setup_styles(self):
        """Configure les styles de l'interface"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Style pour les boutons
        style.configure('Start.TButton', 
                       background='#4CAF50', 
                       foreground='white',
                       font=('Arial', 10, 'bold'))
        style.configure('Stop.TButton', 
                       background='#f44336', 
                       foreground='white',
                       font=('Arial', 10, 'bold'))
        style.configure('Admin.TButton', 
                       background='#FF9800', 
                       foreground='white',
                       font=('Arial', 9, 'bold'))
    
    def create_widgets(self):
        """Créer tous les widgets de l'interface"""
        
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configuration de la grille
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Titre avec indicateur de permissions
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        title_label = tk.Label(title_frame, 
                              text="🔍 DHCP Monitor - Option 50 Tracker",
                              font=('Arial', 16, 'bold'),
                              bg='#2b2b2b', fg='#ffffff')
        title_label.grid(row=0, column=0)
        
        # Indicateur de permissions
        self.permission_label = tk.Label(title_frame, 
                                       text="🔒 Vérification...",
                                       font=('Arial', 10),
                                       bg='#2b2b2b', fg='#ffaa00')
        self.permission_label.grid(row=1, column=0, pady=(5, 0))
        
        # Bouton pour redémarrer avec privilèges
        self.admin_button = ttk.Button(title_frame, text="🔑 Redémarrer en Admin", 
                                      command=self.restart_with_privileges,
                                      style='Admin.TButton')
        self.admin_button.grid(row=1, column=1, padx=(20, 0), pady=(5, 0))
        
        # Frame de configuration
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        config_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        config_frame.columnconfigure(1, weight=1)
        
        # Interface réseau
        ttk.Label(config_frame, text="Interface réseau:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.interface_combo = ttk.Combobox(config_frame, textvariable=self.selected_interface, 
                                           state="readonly", width=30)
        self.interface_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        # Bouton pour recharger les interfaces
        self.refresh_button = ttk.Button(config_frame, text="🔄", 
                                       command=self.load_interfaces, width=3)
        self.refresh_button.grid(row=0, column=2, padx=(5, 0))
        
        # Gateway IP
        ttk.Label(config_frame, text="Gateway IP:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.gateway_entry = ttk.Entry(config_frame, textvariable=self.gateway_ip, width=30)
        self.gateway_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(10, 0))
        self.gateway_entry.insert(0, "192.168.1.1")
        
        # Bouton de validation IP
        self.validate_button = ttk.Button(config_frame, text="Valider IP", 
                                         command=self.validate_gateway_ip)
        self.validate_button.grid(row=1, column=2, padx=(5, 0), pady=(10, 0))
        
        # Frame de contrôle
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        # Boutons de contrôle
        self.start_button = ttk.Button(control_frame, text="🚀 Démarrer la capture", 
                                      command=self.start_monitoring, style='Start.TButton')
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="🛑 Arrêter", 
                                     command=self.stop_monitoring, style='Stop.TButton',
                                     state="disabled")
        self.stop_button.grid(row=0, column=1, padx=5)
        
        self.clear_button = ttk.Button(control_frame, text="🗑️ Effacer les logs", 
                                      command=self.clear_logs)
        self.clear_button.grid(row=0, column=2, padx=5)
        
        # Test de permissions
        self.test_button = ttk.Button(control_frame, text="🧪 Tester permissions", 
                                     command=self.test_permissions)
        self.test_button.grid(row=0, column=3, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("⏹️ Arrêté - Vérification des permissions...")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, 
                                relief=tk.SUNKEN, anchor=tk.W)
        status_label.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 5))
        
        # Frame des logs avec onglets
        log_frame = ttk.LabelFrame(main_frame, text="Logs de capture", padding="5")
        log_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Notebook pour les onglets
        self.notebook = ttk.Notebook(log_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Onglet "Tous les logs"
        all_frame = ttk.Frame(self.notebook)
        self.notebook.add(all_frame, text="📋 Tous les logs")
        
        self.log_text = scrolledtext.ScrolledText(all_frame, height=20, 
                                                 bg='#1e1e1e', fg='#ffffff',
                                                 font=('Consolas', 9))
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        all_frame.columnconfigure(0, weight=1)
        all_frame.rowconfigure(0, weight=1)
        
        # Onglet "Option 50 uniquement"
        option50_frame = ttk.Frame(self.notebook)
        self.notebook.add(option50_frame, text="🎯 Option 50")
        
        self.option50_text = scrolledtext.ScrolledText(option50_frame, height=20,
                                                      bg='#1e1e1e', fg='#00ff00',
                                                      font=('Consolas', 9))
        self.option50_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        option50_frame.columnconfigure(0, weight=1)
        option50_frame.rowconfigure(0, weight=1)
        
        # Onglet "Statistiques"
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📊 Statistiques")
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=20,
                                                   bg='#1e1e1e', fg='#ffff00',
                                                   font=('Consolas', 9))
        self.stats_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.rowconfigure(0, weight=1)
        
        # Initialiser les statistiques
        self.stats = {
            'total_packets': 0,
            'option50_packets': 0,
            'dhcp_types': {},
            'gateway_packets': 0
        }
        
        # Mettre à jour l'indicateur de permissions
        self.update_permission_indicator()
    
    def update_permission_indicator(self):
        """Mettre à jour l'indicateur de permissions"""
        if self.permission_manager.is_admin():
            self.permission_label.config(text="🔓 Privilèges administrateur", fg='#00ff00')
            self.admin_button.grid_remove()
            self.status_var.set("⏹️ Arrêté - Prêt à démarrer")
        else:
            self.permission_label.config(text="🔒 Privilèges limités", fg='#ff4444')
            self.admin_button.grid()
            self.status_var.set("⚠️ Privilèges insuffisants - Capture limitée")
    
    def restart_with_privileges(self):
        """Redémarrer avec des privilèges administrateur"""
        success, error = self.permission_manager.restart_as_admin()
        if not success:
            messagebox.showerror("Erreur", f"Impossible de redémarrer: {error}")
    
    def test_permissions(self):
        """Tester les permissions de capture"""
        self.log_message("🧪 Test des permissions...", "info")
        
        # Test 1: Privilèges administrateur
        if self.permission_manager.is_admin():
            self.log_message("✅ Test 1: Privilèges administrateur - OK", "success")
        else:
            self.log_message("❌ Test 1: Privilèges administrateur - ÉCHEC", "error")
        
        # Test 2: Raw sockets
        if self.permission_manager.check_raw_socket_permission():
            self.log_message("✅ Test 2: Accès raw sockets - OK", "success")
        else:
            self.log_message("❌ Test 2: Accès raw sockets - ÉCHEC", "error")
        
        # Test 3: Scapy
        if SCAPY_AVAILABLE:
            self.log_message("✅ Test 3: Scapy disponible - OK", "success")
        else:
            self.log_message("❌ Test 3: Scapy disponible - ÉCHEC", "error")
        
        # Test 4: Interfaces réseau
        try:
            interfaces = get_if_list() if SCAPY_AVAILABLE else []
            if interfaces:
                self.log_message(f"✅ Test 4: Interfaces réseau ({len(interfaces)} trouvées) - OK", "success")
            else:
                self.log_message("❌ Test 4: Aucune interface réseau trouvée - ÉCHEC", "error")
        except Exception as e:
            self.log_message(f"❌ Test 4: Erreur interfaces - {e}", "error")
        
        # Recommandations
        self.log_message("📋 Recommandations:", "info")
        if not self.permission_manager.is_admin():
            if platform.system() == "Windows":
                self.log_message("  • Redémarrer en tant qu'administrateur", "info")
            else:
                self.log_message("  • Utiliser sudo ou configurer setcap", "info")
        
        if not SCAPY_AVAILABLE:
            self.log_message("  • Installer Scapy: pip install scapy", "info")
    
    def load_interfaces(self):
        """Charger les interfaces réseau disponibles"""
        try:
            if not SCAPY_AVAILABLE:
                self.log_message("❌ Scapy non disponible pour lister les interfaces", "error")
                return
                
            interfaces = get_if_list()
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.current(0)
                self.selected_interface.set(interfaces[0])
                self.log_message(f"✅ {len(interfaces)} interfaces chargées", "success")
            else:
                self.log_message("⚠️ Aucune interface réseau trouvée", "warning")
        except Exception as e:
            self.log_message(f"❌ Erreur lors du chargement des interfaces: {e}", "error")
    
    def validate_ip(self, ip):
        """Valider une adresse IP"""
        pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if not re.match(pattern, ip):
            return False
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    
    def validate_gateway_ip(self):
        """Valider l'adresse IP de la gateway"""
        ip = self.gateway_ip.get().strip()
        if self.validate_ip(ip):
            messagebox.showinfo("✅ Validation", f"Adresse IP {ip} valide!")
            self.log_message(f"✅ Gateway IP validée: {ip}", "success")
        else:
            messagebox.showerror("❌ Erreur", "Adresse IP invalide!\nFormat attendu: xxx.xxx.xxx.xxx")
            
    def log_message(self, message, msg_type="info"):
        """Ajouter un message aux logs"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_msg = f"[{timestamp}] {message}\n"
        
        # Ajouter à la queue pour traitement thread-safe
        self.message_queue.put(('log', formatted_msg, msg_type))
        
    def log_option50(self, message):
        """Ajouter un message spécifiquement pour l'option 50"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_msg = f"[{timestamp}] {message}\n"
        self.message_queue.put(('option50', formatted_msg))
        
    def update_stats(self, packet_info):
        """Mettre à jour les statistiques"""
        self.message_queue.put(('stats', packet_info))
        
    def check_queue(self):
        """Vérifier la queue des messages de manière thread-safe"""
        try:
            while True:
                msg_type, message, *args = self.message_queue.get_nowait()
                
                if msg_type == 'log':
                    self.log_text.insert(tk.END, message)
                    self.log_text.see(tk.END)
                    
                elif msg_type == 'option50':
                    self.option50_text.insert(tk.END, message)
                    self.option50_text.see(tk.END)
                    
                elif msg_type == 'stats':
                    self.process_stats(args[0])
                    
        except queue.Empty:
            pass
        
        # Programmer la prochaine vérification
        self.root.after(100, self.check_queue)
        
    def process_stats(self, packet_info):
        """Traiter les statistiques des paquets"""
        self.stats['total_packets'] += 1
        
        if 'option50' in packet_info:
            self.stats['option50_packets'] += 1
            
        if 'msg_type' in packet_info:
            msg_type = packet_info['msg_type']
            self.stats['dhcp_types'][msg_type] = self.stats['dhcp_types'].get(msg_type, 0) + 1
            
        if packet_info.get('is_gateway', False):
            self.stats['gateway_packets'] += 1
            
        self.update_stats_display()
        
    def update_stats_display(self):
        """Mettre à jour l'affichage des statistiques"""
        stats_text = f"""📊 STATISTIQUES DE CAPTURE
{'='*50}
🔢 Total paquets capturés: {self.stats['total_packets']}
🎯 Paquets avec Option 50: {self.stats['option50_packets']}
🌐 Paquets Gateway: {self.stats['gateway_packets']}

📋 Types de messages DHCP:
"""
        
        dhcp_types = {
            1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
            5: "ACK", 6: "NACK", 7: "RELEASE", 8: "INFORM"
        }
        
        for msg_type, count in self.stats['dhcp_types'].items():
            type_name = dhcp_types.get(msg_type, f"TYPE_{msg_type}")
            stats_text += f"  • {type_name}: {count}\n"
            
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)
        
    def parse_dhcp_options(self, options):
        """Parser les options DHCP"""
        parsed = {}
        for option in options:
            if isinstance(option, tuple) and len(option) == 2:
                opt_code, opt_value = option
                if opt_code == "message-type":
                    parsed['msg_type'] = opt_value
                elif opt_code == "requested_addr":
                    parsed['requested_ip'] = opt_value
                elif opt_code == "server_id":
                    parsed['server_id'] = opt_value
                elif opt_code == "hostname":
                    parsed['hostname'] = opt_value
        return parsed
        
    def get_dhcp_message_type(self, msg_type):
        """Convertir le type de message DHCP"""
        types = {
            1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
            5: "ACK", 6: "NACK", 7: "RELEASE", 8: "INFORM"
        }
        return types.get(msg_type, f"TYPE_{msg_type}")
        
    def dhcp_packet_handler(self, packet):
        """Gestionnaire de paquets DHCP"""
        try:
            if packet.haslayer(DHCP) and packet.haslayer(IP) and packet.haslayer(UDP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                mac_src = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
                
                dhcp_options = self.parse_dhcp_options(packet[DHCP].options)
                
                # Informations du paquet pour les stats
                packet_info = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'is_gateway': src_ip == self.gateway_ip.get() or dst_ip == self.gateway_ip.get()
                }
                
                # Log principal
                log_msg = f"BOOTP/DHCP Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}"
                self.log_message(log_msg)
                self.log_message(f"  └─ MAC: {mac_src}")
                
                if 'msg_type' in dhcp_options:
                    msg_type_str = self.get_dhcp_message_type(dhcp_options['msg_type'])
                    self.log_message(f"  └─ Message Type: {msg_type_str} ({dhcp_options['msg_type']})")
                    packet_info['msg_type'] = dhcp_options['msg_type']
                    
                    # Focus sur l'option 50
                    if 'requested_ip' in dhcp_options:
                        requested_ip = dhcp_options['requested_ip']
                        option50_msg = f"🎯 Option 50 - Requested IP: {requested_ip}"
                        self.log_message(f"  └─ {option50_msg}")
                        self.log_option50(f"{option50_msg} | {src_ip} → {dst_ip} | {msg_type_str}")
                        packet_info['option50'] = requested_ip
                        
                        # Vérification gateway
                        if packet_info['is_gateway']:
                            self.log_message("  └─ 🌐 GATEWAY ACTIVITY DETECTED!", "success")
                            
                    # Autres informations
                    if 'server_id' in dhcp_options:
                        self.log_message(f"  └─ Server ID: {dhcp_options['server_id']}")
                    if 'hostname' in dhcp_options:
                        self.log_message(f"  └─ Hostname: {dhcp_options['hostname']}")
                        
                # Mettre à jour les statistiques
                self.update_stats(packet_info)
                
        except Exception as e:
            self.log_message(f"❌ Erreur lors du traitement du paquet: {e}", "error")
            
    def start_monitoring(self):
        """Démarrer la surveillance DHCP avec gestion d'erreurs améliorée"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Erreur", "Scapy n'est pas disponible!")
            return
            
        gateway = self.gateway_ip.get().strip()
        if not self.validate_ip(gateway):
            messagebox.showerror("Erreur", "Veuillez entrer une adresse IP de gateway valide!")
            return
            
        interface = self.selected_interface.get()
        if not interface:
            messagebox.showerror("Erreur", "Veuillez sélectionner une interface réseau!")
            return
        
        # Vérification des permissions avant de commencer
        if not self.permission_manager.is_admin():
            result = messagebox.askyesno("Permissions insuffisantes", 
                                       "Vous n'avez pas les privilèges administrateur.\n"
                                       "La capture peut échouer.\n\n"
                                       "Continuer quand même?")
            if not result:
                return
            
        self.is_monitoring = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_var.set("🔄 Capture en cours...")
        
        self.log_message("🚀 Démarrage de la capture DHCP", "success")
        self.log_message(f"🌐 Gateway: {gateway}")
        self.log_message(f"🔗 Interface: {interface}")
        self.log_message("🎯 Surveillance des requêtes avec option 50 activée")
        
        # Réinitialiser les statistiques
        self.stats = {'total_packets': 0, 'option50_packets': 0, 'dhcp_types': {}, 'gateway_packets': 0}
        
        # Démarrer le thread de capture
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(interface,))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
    def sniff_packets(self, interface):
        """Thread de capture des paquets avec gestion d'erreurs renforcée"""
        try:
            self.log_message(f"🔍 Début de la capture sur {interface}...", "info")
            
            # Configuration de Scapy pour éviter certains problèmes
            conf.use_pcap = True  # Forcer l'utilisation de pcap si disponible
            
            sniff(filter="udp and (port 67 or port 68)",
                  prn=self.dhcp_packet_handler,
                  store=0,
                  iface=interface,
                  stop_filter=lambda x: not self.is_monitoring,
                  timeout=1)  # Timeout pour éviter le blocage
                  
        except PermissionError as e:
            self.log_message(f"❌ Erreur de permissions: {e}", "error")
            self.log_message("💡 Solution: Redémarrer en tant qu'administrateur", "info")
            self.message_queue.put(('permission_error', str(e)))
        except OSError as e:
            self.log_message(f"❌ Erreur système: {e}", "error")
            if "Operation not permitted" in str(e):
                self.log_message("💡 Vérifiez les privilèges administrateur", "info")
            elif "No such device" in str(e):
                self.log_message("💡 Interface réseau introuvable", "info")
            self.message_queue.put(('os_error', str(e)))
        except Exception as e:
            self.log_message(f"❌ Erreur de capture: {e}", "error")
            self.log_message(f"📝 Type d'erreur: {type(e).__name__}", "info")
        finally:
            if self.is_monitoring:
                self.message_queue.put(('capture_ended', "Capture terminée de manière inattendue"))
            
    def stop_monitoring(self):
        """Arrêter la surveillance"""
        self.is_monitoring = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_var.set("⏹️ Arrêté")
        self.log_message("🛑 Capture arrêtée", "info")
        
    def clear_logs(self):
        """Effacer tous les logs"""
        self.log_text.delete(1.0, tk.END)
        self.option50_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.stats = {'total_packets': 0, 'option50_packets': 0, 'dhcp_types': {}, 'gateway_packets': 0}
        self.log_message("🗑️ Logs effacés", "info")

class SetupWizard:
    """Assistant de configuration pour résoudre les problèmes de permissions"""
    
    def __init__(self, parent):
        self.parent = parent
        self.window = None
        
    def show_setup_wizard(self):
        """Afficher l'assistant de configuration"""
        self.window = tk.Toplevel(self.parent)
        self.window.title("🔧 Assistant de Configuration")
        self.window.geometry("600x500")
        self.window.configure(bg='#2b2b2b')
        self.window.transient(self.parent)
        self.window.grab_set()
        
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        
        # Titre
        title = tk.Label(main_frame, text="🔧 Assistant de Configuration DHCP Monitor",
                        font=('Arial', 14, 'bold'), bg='#2b2b2b', fg='#ffffff')
        title.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Diagnostic automatique
        diag_frame = ttk.LabelFrame(main_frame, text="Diagnostic", padding="10")
        diag_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.diag_text = scrolledtext.ScrolledText(diag_frame, height=8, width=70,
                                                  bg='#1e1e1e', fg='#ffffff',
                                                  font=('Consolas', 9))
        self.diag_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Boutons d'action
        action_frame = ttk.LabelFrame(main_frame, text="Actions", padding="10")
        action_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        if platform.system() == "Windows":
            ttk.Button(action_frame, text="🔑 Redémarrer en Administrateur",
                      command=self.restart_as_admin).grid(row=0, column=0, padx=5, pady=5)
            ttk.Button(action_frame, text="📖 Guide Windows",
                      command=self.show_windows_guide).grid(row=0, column=1, padx=5, pady=5)
        else:
            ttk.Button(action_frame, text="🔑 Utiliser sudo",
                      command=self.restart_with_sudo).grid(row=0, column=0, padx=5, pady=5)
            ttk.Button(action_frame, text="⚙️ Configurer setcap",
                      command=self.setup_setcap).grid(row=0, column=1, padx=5, pady=5)
            ttk.Button(action_frame, text="📖 Guide Linux",
                      command=self.show_linux_guide).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Button(action_frame, text="🧪 Tester Configuration",
                  command=self.test_configuration).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(action_frame, text="❌ Fermer",
                  command=self.window.destroy).grid(row=1, column=1, padx=5, pady=5)
        
        # Lancer le diagnostic automatique
        self.run_diagnosis()
        
    def run_diagnosis(self):
        """Exécuter un diagnostic complet"""
        self.diag_text.delete(1.0, tk.END)
        self.diag_text.insert(tk.END, "🔍 Diagnostic en cours...\n\n")
        
        # Vérifications
        checks = [
            ("Système d'exploitation", self.check_os),
            ("Privilèges administrateur", self.check_admin),
            ("Installation Scapy", self.check_scapy),
            ("Accès raw sockets", self.check_raw_sockets),
            ("Interfaces réseau", self.check_interfaces)
        ]
        
        for check_name, check_func in checks:
            result, message = check_func()
            status = "✅" if result else "❌"
            self.diag_text.insert(tk.END, f"{status} {check_name}: {message}\n")
            
        self.diag_text.insert(tk.END, "\n📋 Recommandations:\n")
        self.diag_text.insert(tk.END, self.get_recommendations())
        
    def check_os(self):
        """Vérifier le système d'exploitation"""
        os_name = platform.system()
        version = platform.release()
        return True, f"{os_name} {version}"
        
    def check_admin(self):
        """Vérifier les privilèges administrateur"""
        is_admin = PermissionManager.is_admin()
        if is_admin:
            return True, "Privilèges administrateur détectés"
        else:
            return False, "Privilèges administrateur requis"
            
    def check_scapy(self):
        """Vérifier l'installation de Scapy"""
        if SCAPY_AVAILABLE:
            try:
                from scapy import VERSION
                return True, f"Scapy {VERSION} installé"
            except:
                return True, "Scapy installé"
        else:
            return False, "Scapy non installé (pip install scapy)"
            
    def check_raw_sockets(self):
        """Vérifier l'accès aux raw sockets"""
        can_access = PermissionManager.check_raw_socket_permission()
        if can_access:
            return True, "Accès raw sockets disponible"
        else:
            return False, "Accès raw sockets refusé"
            
    def check_interfaces(self):
        """Vérifier les interfaces réseau"""
        try:
            if SCAPY_AVAILABLE:
                interfaces = get_if_list()
                return True, f"{len(interfaces)} interfaces trouvées"
            else:
                return False, "Impossible de lister (Scapy requis)"
        except Exception as e:
            return False, f"Erreur: {str(e)}"
            
    def get_recommendations(self):
        """Obtenir les recommandations basées sur le diagnostic"""
        recommendations = []
        
        if not PermissionManager.is_admin():
            if platform.system() == "Windows":
                recommendations.append("• Clic droit sur l'application → 'Exécuter en tant qu'administrateur'")
            else:
                recommendations.append("• Utiliser 'sudo python3 script.py' ou configurer setcap")
                
        if not SCAPY_AVAILABLE:
            recommendations.append("• Installer Scapy: pip install scapy")
            
        if not PermissionManager.check_raw_socket_permission():
            recommendations.append("• Vérifier les permissions réseau")
            
        if not recommendations:
            recommendations.append("• Configuration semble correcte!")
            
        return "\n".join(recommendations)
        
    def restart_as_admin(self):
        """Redémarrer en tant qu'administrateur"""
        PermissionManager.restart_as_admin()
        
    def restart_with_sudo(self):
        """Redémarrer avec sudo"""
        PermissionManager.restart_as_admin()
        
    def setup_setcap(self):
        """Configurer setcap pour Linux"""
        success, message = PermissionManager.setup_linux_permissions()
        messagebox.showinfo("Configuration setcap", message)
        
    def show_windows_guide(self):
        """Afficher le guide Windows"""
        guide = """Guide Windows - Capture réseau avec privilèges

1. Méthode recommandée:
   • Clic droit sur l'application Python
   • Sélectionner "Exécuter en tant qu'administrateur"

2. Alternative - Invite de commandes:
   • Ouvrir "cmd" en tant qu'administrateur
   • Naviguer vers le dossier du script
   • Exécuter: python dhcp_monitor.py

3. Troubleshooting:
   • Vérifier que Python est dans le PATH
   • Installer Scapy: pip install scapy
   • Désactiver temporairement l'antivirus si nécessaire

4. Permissions requises:
   • Capture de paquets réseau
   • Accès aux interfaces réseau
   • Lecture des configurations réseau"""
        
        messagebox.showinfo("Guide Windows", guide)
        
    def show_linux_guide(self):
        """Afficher le guide Linux"""
        guide = """Guide Linux - Capture réseau avec privilèges

1. Méthode sudo (simple):
   sudo python3 dhcp_monitor.py

2. Méthode setcap (recommandée):
   sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3
   
3. Alternative - Groupe netdev:
   sudo usermod -a -G netdev $USER
   (redémarrage requis)

4. Vérification des permissions:
   getcap /usr/bin/python3

5. Troubleshooting:
   • Installer Scapy: pip3 install scapy
   • Vérifier les interfaces: ip link show
   • Logs système: journalctl -f"""
        
        messagebox.showinfo("Guide Linux", guide)
        
    def test_configuration(self):
        """Tester la configuration actuelle"""
        self.run_diagnosis()

def main():
    """Fonction principale avec gestion complète des erreurs"""
    
    # Créer la fenêtre principale
    root = tk.Tk()
    
    # Créer l'application
    app = DHCPMonitorGUI(root)
    
    # Ajouter le menu
    menubar = tk.Menu(root)
    root.config(menu=menubar)
    
    # Menu Aide
    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Aide", menu=help_menu)
    help_menu.add_command(label="🔧 Assistant de Configuration", 
                         command=lambda: SetupWizard(root).show_setup_wizard())
    help_menu.add_separator()
    help_menu.add_command(label="📖 À propos", command=show_about)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.stop_monitoring()
    except Exception as e:
        messagebox.showerror("Erreur critique", f"Erreur inattendue: {e}")

def show_about():
    """Afficher les informations sur l'application"""
    about_text = """🔍 DHCP Monitor - Option 50 Tracker

Version: 2.0 (avec gestion des permissions)
Auteur: Assistant IA
Licence: Open Source

Fonctionnalités:
• Capture en temps réel des paquets DHCP
• Surveillance spécifique de l'option 50
• Interface graphique moderne
• Gestion avancée des permissions
• Statistiques détaillées
• Multi-plateforme (Windows/Linux)

Permissions requises:
• Capture de paquets réseau (raw sockets)
• Accès aux interfaces réseau
• Privilèges administrateur/root

Support:
• Windows: Exécuter en tant qu'administrateur
• Linux: sudo ou configuration setcap"""
    
    messagebox.showinfo("À propos", about_text)

if __name__ == "__main__":
    main()
