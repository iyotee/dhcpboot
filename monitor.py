#!/usr/bin/env python3
"""
DHCP Monitor GUI - Version moderne avec CustomTkinter
Surveillance DHCP avec interface graphique ultra-moderne, coloration des logs et graphiques
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import queue
import re
import subprocess
import sys
import os
import platform
from datetime import datetime
import json
from collections import deque
import matplotlib
matplotlib.use('TkAgg')  # S'assurer d'utiliser le backend TkAgg
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import matplotlib.dates as mdates
import warnings

# Supprimer les avertissements matplotlib sur les glyphes manquants
warnings.filterwarnings("ignore", category=UserWarning, module="matplotlib")

# Configuration matplotlib pour éviter les problèmes d'emojis
plt.rcParams['font.family'] = ['DejaVu Sans', 'Arial', 'sans-serif']

# Configuration CustomTkinter
ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

# Import conditionnel de Scapy avec gestion d'erreur
try:
    from scapy.all import sniff, DHCP, IP, Ether, UDP, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Couleurs pour les logs
LOG_COLORS = {
    "success": "#00ff00",      # Vert
    "error": "#ff4444",        # Rouge
    "warning": "#ffaa00",      # Orange
    "info": "#66ccff",         # Bleu clair
    "option50": "#ff66ff",     # Magenta vif
    "gateway": "#00ffaa",      # Cyan vert
    "ip_address": "#ffff00",   # Jaune vif pour les IPs
    "mac_address": "#ff8800",  # Orange pour les MACs
    "port": "#88ff88",         # Vert clair pour les ports
    "hostname": "#ffaa88",     # Orange clair pour hostnames
    "vendor": "#88aaff",       # Bleu clair pour vendors
    "server_id": "#aaffaa",    # Vert pâle pour server ID
    "timestamp": "#cccccc",    # Gris clair pour timestamps
    "default": "#ffffff"       # Blanc
}

class NetworkGraphs:
    """Gestionnaire des graphiques réseau en temps réel"""
    
    def __init__(self, parent_frame):
        self.parent_frame = parent_frame
        self.packet_times = deque(maxlen=100)
        self.packet_counts = deque(maxlen=100)
        self.option50_times = deque(maxlen=100)
        self.option50_counts = deque(maxlen=100)
        
        # Créer la figure matplotlib
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(10, 6))
        self.fig.patch.set_facecolor('#2b2b2b')
        
        # Configuration des axes
        self.ax1.set_facecolor('#1e1e1e')
        self.ax2.set_facecolor('#1e1e1e')
        
        self.ax1.set_title('Trafic DHCP Total', color='white', fontsize=12)
        self.ax2.set_title('Trafic Option 50', color='white', fontsize=12)
        
        for ax in [self.ax1, self.ax2]:
            ax.tick_params(colors='white')
            ax.spines['bottom'].set_color('white')
            ax.spines['top'].set_color('white')
            ax.spines['right'].set_color('white')
            ax.spines['left'].set_color('white')
        
        # Intégrer dans tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, self.parent_frame)
        self.canvas.get_tk_widget().grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
        
        # Lignes pour les graphiques
        self.line1, = self.ax1.plot([], [], 'cyan', linewidth=2, label='Paquets DHCP')
        self.line2, = self.ax2.plot([], [], 'magenta', linewidth=2, label='Option 50')
        
        self.ax1.legend(loc='upper left')
        self.ax2.legend(loc='upper left')
        
        # Initialisation des données
        self.reset_data()
    
    def reset_data(self):
        """Réinitialiser les données du graphique"""
        self.packet_times.clear()
        self.packet_counts.clear()
        self.option50_times.clear()
        self.option50_counts.clear()
        
        # Ajouter quelques points de base
        now = datetime.now()
        for i in range(10):
            time_point = datetime.now()
            self.packet_times.append(time_point)
            self.packet_counts.append(0)
            self.option50_times.append(time_point)
            self.option50_counts.append(0)
    
    def add_packet_data(self, is_option50=False):
        """Ajouter un point de données pour un nouveau paquet"""
        now = datetime.now()
        
        # Ajouter pour trafic total
        self.packet_times.append(now)
        current_count = self.packet_counts[-1] + 1 if self.packet_counts else 1
        self.packet_counts.append(current_count)
        
        # Ajouter pour Option 50 si applicable
        if is_option50:
            self.option50_times.append(now)
            current_option50 = self.option50_counts[-1] + 1 if self.option50_counts else 1
            self.option50_counts.append(current_option50)
        else:
            # Ajouter un point avec la même valeur
            self.option50_times.append(now)
            current_option50 = self.option50_counts[-1] if self.option50_counts else 0
            self.option50_counts.append(current_option50)
    
    def update_graphs(self):
        """Mettre à jour les graphiques"""
        if not self.packet_times:
            return
        
        # Convertir en listes pour matplotlib
        times1 = list(self.packet_times)
        counts1 = list(self.packet_counts)
        times2 = list(self.option50_times)
        counts2 = list(self.option50_counts)
        
        # Mettre à jour les lignes
        self.line1.set_data(times1, counts1)
        self.line2.set_data(times2, counts2)
        
        # Ajuster les axes
        if times1:
            self.ax1.set_xlim(times1[0], times1[-1])
            self.ax1.set_ylim(0, max(counts1) + 1 if counts1 else 1)
            
        if times2:
            self.ax2.set_xlim(times2[0], times2[-1])
            self.ax2.set_ylim(0, max(counts2) + 1 if counts2 else 1)
        
        # Formater les axes temporels
        for ax in [self.ax1, self.ax2]:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
            ax.xaxis.set_major_locator(mdates.SecondLocator(interval=10))
        
        # Redessiner
        self.canvas.draw()

class ColoredTextbox(ctk.CTkTextbox):
    """Textbox personnalisée avec support de la coloration avancée"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure_tags()
    
    def configure_tags(self):
        """Configurer les tags de couleur"""
        for tag_name, color in LOG_COLORS.items():
            self.tag_config(tag_name, foreground=color)
    
    def insert_colored(self, index, text, color_type="default"):
        """Insérer du texte avec couleur"""
        start_index = self.index(index)
        self.insert(index, text)
        end_index = self.index(f"{start_index}+{len(text)}c")
        self.tag_add(color_type, start_index, end_index)
        
    def append_colored(self, text, color_type="default"):
        """Ajouter du texte coloré à la fin"""
        self.insert_colored("end", text, color_type)
    
    def append_mixed_colored(self, text_parts):
        """Ajouter du texte avec plusieurs couleurs
        text_parts: liste de tuples (text, color_type)
        """
        for text, color_type in text_parts:
            self.append_colored(text, color_type)

def extract_and_color_ips(text):
    """Extraire et colorer les adresses IP dans un texte"""
    import re
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    parts = []
    last_end = 0
    
    for match in re.finditer(ip_pattern, text):
        # Ajouter le texte avant l'IP
        if match.start() > last_end:
            parts.append((text[last_end:match.start()], "default"))
        
        # Ajouter l'IP avec sa couleur
        parts.append((match.group(), "ip_address"))
        last_end = match.end()
    
    # Ajouter le reste du texte
    if last_end < len(text):
        parts.append((text[last_end:], "default"))
    
    return parts

def extract_and_color_macs(text):
    """Extraire et colorer les adresses MAC dans un texte"""
    import re
    mac_pattern = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
    parts = []
    last_end = 0
    
    for match in re.finditer(mac_pattern, text):
        # Ajouter le texte avant la MAC
        if match.start() > last_end:
            parts.append((text[last_end:match.start()], "default"))
        
        # Ajouter la MAC avec sa couleur
        parts.append((match.group(), "mac_address"))
        last_end = match.end()
    
    # Ajouter le reste du texte
    if last_end < len(text):
        parts.append((text[last_end:], "default"))
    
    return parts

def extract_and_color_ports(text):
    """Extraire et colorer les ports dans un texte"""
    import re
    port_pattern = r':(\d{1,5})\b'
    parts = []
    last_end = 0
    
    for match in re.finditer(port_pattern, text):
        # Ajouter le texte avant le port (incluant ':')
        if match.start() > last_end:
            parts.append((text[last_end:match.start()+1], "default"))
        
        # Ajouter le port avec sa couleur
        parts.append((match.group(1), "port"))
        last_end = match.end()
    
    # Ajouter le reste du texte
    if last_end < len(text):
        parts.append((text[last_end:], "default"))
    
    return parts

def colorize_log_message(message):
    """Coloriser un message de log de manière intelligente"""
    # D'abord traiter les IPs
    parts = extract_and_color_ips(message)
    
    # Puis traiter les MACs sur chaque partie
    final_parts = []
    for text, color in parts:
        if color == "default":
            mac_parts = extract_and_color_macs(text)
            final_parts.extend(mac_parts)
        else:
            final_parts.append((text, color))
    
    # Puis traiter les ports
    colored_parts = []
    for text, color in final_parts:
        if color == "default":
            port_parts = extract_and_color_ports(text)
            colored_parts.extend(port_parts)
        else:
            colored_parts.append((text, color))
    
    return colored_parts

# Fonction pour obtenir des noms d'interfaces plus lisibles sous Windows
def get_readable_interfaces():
    """Obtenir des noms d'interfaces réseau plus lisibles sous Windows"""
    if platform.system() != "Windows":
        return get_if_list(), {}  # Sur non-Windows, retourner simplement la liste
    
    # Sur Windows, essayer d'obtenir des noms plus descriptifs
    interfaces = get_if_list()
    readable_names = {}
    
    try:
        # Méthode 1: Utiliser le registre Windows pour obtenir les noms d'interfaces
        try:
            import winreg
            
            # Clé de registre contenant les informations sur les interfaces réseau
            reg_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as network_key:
                i = 0
                while True:
                    try:
                        # Énumérer les sous-clés (GUIDs des interfaces)
                        interface_guid = winreg.EnumKey(network_key, i)
                        
                        # Ouvrir la sous-clé Connection pour obtenir le nom
                        connection_path = f"{reg_path}\\{interface_guid}\\Connection"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, connection_path) as conn_key:
                                try:
                                    # Lire le nom de l'interface
                                    name, _ = winreg.QueryValueEx(conn_key, "Name")
                                    
                                    # Chercher l'interface Scapy correspondante
                                    scapy_interface = f"\\Device\\NPF_{{{interface_guid}}}"
                                    if scapy_interface in interfaces:
                                        readable_names[scapy_interface] = name
                                except FileNotFoundError:
                                    pass
                        except FileNotFoundError:
                            pass
                        i += 1
                    except OSError:
                        break
                        
        except ImportError:
            pass
        except Exception:
            pass
        
        # Méthode 2: Utiliser PowerShell avec Get-NetAdapter et correspondance par nom
        if not readable_names:
            try:
                # Obtenir les informations des adaptateurs avec PowerShell
                cmd = ["powershell", "-Command", 
                       "Get-NetAdapter | Select-Object Name,InterfaceGuid,InterfaceDescription | ConvertTo-Json"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    adapters = json.loads(result.stdout)
                    
                    # Si c'est un seul adaptateur, le mettre dans une liste
                    if isinstance(adapters, dict):
                        adapters = [adapters]
                    
                    for adapter in adapters:
                        if 'InterfaceGuid' in adapter and 'Name' in adapter:
                            guid = adapter['InterfaceGuid'].strip('{}')
                            name = adapter['Name']
                            scapy_interface = f"\\Device\\NPF_{{{guid}}}"
                            
                            if scapy_interface in interfaces:
                                readable_names[scapy_interface] = name
                                
            except Exception:
                pass
        
        # Méthode de secours: noms simplifiés
        for idx, iface in enumerate(interfaces):
            if iface not in readable_names:
                # Extraire le GUID et créer un nom simplifié
                guid_match = re.search(r'{(.*?)}', iface)
                if guid_match:
                    guid = guid_match.group(1)
                    readable_names[iface] = f"Interface {idx+1} ({guid[:8]})"
                else:
                    readable_names[iface] = f"Interface {idx+1}"
                    
    except Exception:
        # En cas d'erreur, utiliser des noms simplifiés
        for idx, iface in enumerate(interfaces):
            readable_names[iface] = f"Interface {idx+1}"
    
    return interfaces, readable_names

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
            # Si nous obtenons une autre erreur, supposons que c'est bon
            # car l'erreur pourrait être liée à autre chose que les permissions
            return True

class DHCPMonitorGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Configuration de la fenêtre principale
        self.title("🔍 DHCP Monitor - Option 50 Tracker")
        self.geometry("1600x1000")  # Plus grande fenêtre
        self.minsize(1400, 800)     # Minimum plus grand
        
        # Variables de contrôle
        self.is_monitoring = False
        self.is_closing = False  # Nouvelle variable pour gérer la fermeture
        self.sniff_thread = None
        self.message_queue = queue.Queue()
        self.gateway_ip = tk.StringVar()
        self.selected_interface = tk.StringVar()
        self.permission_manager = PermissionManager()
        self.interface_mapping = {}  # Mapping entre les noms affichés et les noms réels
        
        # Variables pour les callbacks
        self.queue_check_id = None
        self.graph_update_id = None
        
        # Créer l'interface moderne
        self.create_modern_interface()
        
        # Vérifier les permissions et Scapy
        self.check_environment()
        
        # Démarrer la vérification de la queue
        self.check_queue()
        
        # Protocole de fermeture
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def create_modern_interface(self):
        """Créer l'interface moderne avec CustomTkinter"""
        
        # Configurer la grille principale
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Sidebar gauche
        self.create_sidebar()
        
        # Frame principal
        self.create_main_frame()
        
        # Initialiser les statistiques
        self.stats = {
            'total_packets': 0,
            'option50_packets': 0,
            'dhcp_types': {},
            'gateway_packets': 0
        }
    
    def create_sidebar(self):
        """Créer la sidebar moderne"""
        self.sidebar_frame = ctk.CTkFrame(self, width=350, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        
        # Titre de l'application
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, 
                                      text="🔍 DHCP Monitor",
                                      font=ctk.CTkFont(size=26, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=25, pady=(25, 15))
        
        self.subtitle_label = ctk.CTkLabel(self.sidebar_frame, 
                                          text="Option 50 Tracker",
                                          font=ctk.CTkFont(size=16))
        self.subtitle_label.grid(row=1, column=0, padx=25, pady=(0, 25))
        
        # Section Configuration
        self.config_label = ctk.CTkLabel(self.sidebar_frame, 
                                        text="⚙️ Configuration",
                                        font=ctk.CTkFont(size=18, weight="bold"))
        self.config_label.grid(row=2, column=0, padx=25, pady=(25, 15))
        
        # Interface réseau
        self.interface_label = ctk.CTkLabel(self.sidebar_frame, 
                                           text="Interface réseau:",
                                           font=ctk.CTkFont(size=14))
        self.interface_label.grid(row=3, column=0, padx=25, pady=(15, 8), sticky="w")
        
        self.interface_combo = ctk.CTkComboBox(self.sidebar_frame, 
                                              variable=self.selected_interface,
                                              state="readonly",
                                              width=300,
                                              height=35,
                                              font=ctk.CTkFont(size=13),
                                              values=["Chargement..."])  # Valeur par défaut
        self.interface_combo.grid(row=4, column=0, padx=25, pady=(0, 15))
        
        # Bouton refresh interfaces
        self.refresh_button = ctk.CTkButton(self.sidebar_frame, 
                                           text="🔄 Actualiser",
                                           command=self.load_interfaces,
                                           width=150,
                                           height=35,
                                           font=ctk.CTkFont(size=13))
        self.refresh_button.grid(row=5, column=0, padx=25, pady=(0, 25))
        
        # Gateway IP
        self.gateway_label = ctk.CTkLabel(self.sidebar_frame, 
                                         text="Gateway IP:",
                                         font=ctk.CTkFont(size=14))
        self.gateway_label.grid(row=6, column=0, padx=25, pady=(15, 8), sticky="w")
        
        self.gateway_entry = ctk.CTkEntry(self.sidebar_frame, 
                                         textvariable=self.gateway_ip,
                                         placeholder_text="192.168.1.1",
                                         width=300,
                                         height=35,
                                         font=ctk.CTkFont(size=13))
        self.gateway_entry.grid(row=7, column=0, padx=25, pady=(0, 15))
        self.gateway_entry.insert(0, "192.168.1.1")
        
        # Bouton validation IP
        self.validate_button = ctk.CTkButton(self.sidebar_frame, 
                                           text="✅ Valider IP",
                                           command=self.validate_gateway_ip,
                                           width=150,
                                           height=35,
                                           font=ctk.CTkFont(size=13))
        self.validate_button.grid(row=8, column=0, padx=25, pady=(0, 25))
        
        # Section Contrôles
        self.control_label = ctk.CTkLabel(self.sidebar_frame, 
                                         text="🎮 Contrôles",
                                         font=ctk.CTkFont(size=18, weight="bold"))
        self.control_label.grid(row=9, column=0, padx=25, pady=(25, 15))
        
        # Boutons de contrôle
        self.start_button = ctk.CTkButton(self.sidebar_frame, 
                                         text="🚀 Démarrer la capture",
                                         command=self.start_monitoring,
                                         width=300,
                                         height=45,
                                         font=ctk.CTkFont(size=15, weight="bold"))
        self.start_button.grid(row=10, column=0, padx=25, pady=(0, 15))
        
        self.stop_button = ctk.CTkButton(self.sidebar_frame, 
                                        text="🛑 Arrêter",
                                        command=self.stop_monitoring,
                                        width=300,
                                        height=45,
                                        fg_color="transparent",
                                        border_width=2,
                                        text_color=("gray10", "#DCE4EE"),
                                        font=ctk.CTkFont(size=15, weight="bold"),
                                        state="disabled")
        self.stop_button.grid(row=11, column=0, padx=25, pady=(0, 15))
        
        # Section Outils
        self.tools_label = ctk.CTkLabel(self.sidebar_frame, 
                                       text="🔧 Outils",
                                       font=ctk.CTkFont(size=18, weight="bold"))
        self.tools_label.grid(row=12, column=0, padx=25, pady=(25, 15))
        
        self.test_button = ctk.CTkButton(self.sidebar_frame, 
                                        text="🧪 Tester permissions",
                                        command=self.test_permissions,
                                        width=300,
                                        height=40,
                                        font=ctk.CTkFont(size=13))
        self.test_button.grid(row=13, column=0, padx=25, pady=(0, 12))
        
        self.admin_button = ctk.CTkButton(self.sidebar_frame, 
                                         text="🔑 Mode Admin",
                                         command=self.restart_with_privileges,
                                         width=300,
                                         height=40,
                                         fg_color="orange",
                                         hover_color="darkorange",
                                         font=ctk.CTkFont(size=13))
        self.admin_button.grid(row=14, column=0, padx=25, pady=(0, 12))
        
        self.clear_button = ctk.CTkButton(self.sidebar_frame, 
                                         text="🗑️ Effacer logs",
                                         command=self.clear_logs,
                                         width=300,
                                         height=40,
                                         font=ctk.CTkFont(size=13))
        self.clear_button.grid(row=15, column=0, padx=25, pady=(0, 25))
        
        # Sélecteur d'apparence
        self.appearance_mode_label = ctk.CTkLabel(self.sidebar_frame, 
                                                 text="Thème d'apparence:",
                                                 font=ctk.CTkFont(size=14),
                                                 anchor="w")
        self.appearance_mode_label.grid(row=16, column=0, padx=25, pady=(25, 8), sticky="w")
        
        self.appearance_mode_optionemenu = ctk.CTkOptionMenu(self.sidebar_frame,
                                                           values=["Light", "Dark", "System"],
                                                           command=self.change_appearance_mode_event,
                                                           width=200,
                                                           height=35,
                                                           font=ctk.CTkFont(size=13))
        self.appearance_mode_optionemenu.grid(row=17, column=0, padx=25, pady=(0, 15))
        
        # Indicateur de permissions
        self.permission_label = ctk.CTkLabel(self.sidebar_frame, 
                                           text="🔒 Vérification...",
                                           font=ctk.CTkFont(size=13))
        self.permission_label.grid(row=18, column=0, padx=25, pady=(15, 25))
    
    def create_main_frame(self):
        """Créer le frame principal avec les onglets"""
        # Frame principal
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, rowspan=4, sticky="nsew", padx=(25, 25), pady=(25, 25))
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        
        # En-tête avec statut
        self.status_frame = ctk.CTkFrame(self.main_frame)
        self.status_frame.grid(row=0, column=0, sticky="ew", padx=25, pady=(25, 15))
        self.status_frame.grid_columnconfigure(0, weight=1)
        
        self.status_label = ctk.CTkLabel(self.status_frame, 
                                        text="⏹️ Arrêté - Prêt à démarrer",
                                        font=ctk.CTkFont(size=16))
        self.status_label.grid(row=0, column=0, padx=25, pady=15, sticky="w")
        
        self.system_info_label = ctk.CTkLabel(self.status_frame, 
                                             text=f"🖥️ {platform.system()} | 🐍 Python {platform.python_version()}",
                                             font=ctk.CTkFont(size=13))
        self.system_info_label.grid(row=0, column=1, padx=25, pady=15, sticky="e")
        
        # Tabview pour les onglets
        self.tabview = ctk.CTkTabview(self.main_frame, width=900, height=700)
        self.tabview.grid(row=1, column=0, padx=25, pady=(0, 25), sticky="nsew")
        
        # Onglets
        self.tabview.add("📋 Tous les logs")
        self.tabview.add("🎯 Option 50")
        self.tabview.add("📊 Statistiques")
        self.tabview.add("📈 Graphiques")
        self.tabview.add("🌐 Réseau")
        
        # Contenu des onglets
        self.create_logs_tab()
        self.create_option50_tab()
        self.create_stats_tab()
        self.create_graphs_tab()
        self.create_network_tab()
    
    def create_logs_tab(self):
        """Créer l'onglet des logs"""
        # Frame pour tous les logs
        logs_frame = self.tabview.tab("📋 Tous les logs")
        logs_frame.grid_columnconfigure(0, weight=1)
        logs_frame.grid_rowconfigure(0, weight=1)
        
        # Zone de texte pour les logs
        self.log_text = ColoredTextbox(logs_frame, 
                                      font=ctk.CTkFont(family="Consolas", size=12),  # Plus grand
                                      wrap="word")
        self.log_text.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
    
    def create_option50_tab(self):
        """Créer l'onglet Option 50"""
        # Frame pour Option 50
        option50_frame = self.tabview.tab("🎯 Option 50")
        option50_frame.grid_columnconfigure(0, weight=1)
        option50_frame.grid_rowconfigure(0, weight=1)
        
        # Zone de texte pour Option 50
        self.option50_text = ColoredTextbox(option50_frame,
                                           font=ctk.CTkFont(family="Consolas", size=12),  # Plus grand
                                           wrap="word")
        self.option50_text.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
    
    def create_stats_tab(self):
        """Créer l'onglet des statistiques"""
        # Frame pour les statistiques
        stats_frame = self.tabview.tab("📊 Statistiques")
        stats_frame.grid_columnconfigure(0, weight=1)
        stats_frame.grid_rowconfigure(0, weight=1)
        
        # Zone de texte pour les statistiques
        self.stats_text = ColoredTextbox(stats_frame,
                                        font=ctk.CTkFont(family="Consolas", size=12),  # Plus grand
                                        wrap="word")
        self.stats_text.grid(row=0, column=0, padx=15, pady=15, sticky="nsew")
    
    def create_graphs_tab(self):
        """Créer l'onglet des graphiques"""
        # Frame pour les graphiques
        graphs_frame = self.tabview.tab("📈 Graphiques")
        graphs_frame.grid_columnconfigure(0, weight=1)
        graphs_frame.grid_rowconfigure(0, weight=1)
        
        # Créer le gestionnaire de graphiques
        self.network_graphs = NetworkGraphs(graphs_frame)
        
        # Boutons de contrôle pour les graphiques
        controls_frame = ctk.CTkFrame(graphs_frame)
        controls_frame.grid(row=1, column=0, padx=15, pady=(8, 15), sticky="ew")
        
        reset_graph_btn = ctk.CTkButton(controls_frame, 
                                       text="🔄 Réinitialiser les graphiques",
                                       command=self.reset_graphs,
                                       height=35,
                                       font=ctk.CTkFont(size=12))
        reset_graph_btn.pack(side="left", padx=10, pady=10)
        
        # Label d'information
        info_label = ctk.CTkLabel(controls_frame, 
                                 text="📊 Graphiques en temps réel du trafic DHCP (comme Wireshark)",
                                 font=ctk.CTkFont(size=11))
        info_label.pack(side="right", padx=10, pady=10)
    
    def create_network_tab(self):
        """Créer l'onglet de configuration réseau"""
        # Frame pour les informations réseau
        network_frame = self.tabview.tab("🌐 Réseau")
        network_frame.grid_columnconfigure(0, weight=1)
        network_frame.grid_rowconfigure(0, weight=1)
        
        # Zone de texte pour les informations réseau
        self.network_info_text = ColoredTextbox(network_frame,
                                               font=ctk.CTkFont(family="Consolas", size=12),  # Plus grand
                                               wrap="word")
        self.network_info_text.grid(row=0, column=0, padx=15, pady=(15, 8), sticky="nsew")
        
        # Bouton pour actualiser les informations réseau
        self.refresh_network_button = ctk.CTkButton(network_frame, 
                                                   text="🔄 Actualiser les informations réseau",
                                                   command=self.refresh_network_info,
                                                   height=40,    # Plus haut
                                                   font=ctk.CTkFont(size=13))
        self.refresh_network_button.grid(row=1, column=0, padx=15, pady=(8, 15))
    
    def change_appearance_mode_event(self, new_appearance_mode: str):
        """Changer le mode d'apparence"""
        ctk.set_appearance_mode(new_appearance_mode)
        self.log_message(f"🎨 Thème changé: {new_appearance_mode}", "info")
    
    def update_permission_indicator(self):
        """Mettre à jour l'indicateur de permissions"""
        if self.permission_manager.is_admin():
            self.permission_label.configure(text="🔓 Privilèges administrateur", 
                                           text_color="green")
            self.status_label.configure(text="⏹️ Arrêté - Prêt à démarrer")
        else:
            self.permission_label.configure(text="🔒 Privilèges limités", 
                                           text_color="red")
            self.status_label.configure(text="⚠️ Privilèges insuffisants - Capture limitée")
    
    def refresh_network_info(self):
        """Actualiser les informations réseau"""
        self.network_info_text.delete("0.0", "end")
        
        info = "🌐 INFORMATIONS RÉSEAU\n"
        info += "=" * 50 + "\n\n"
        
        try:
            # Informations sur les interfaces
            interfaces, readable_names = get_readable_interfaces()
            
            info += f"📡 Interfaces réseau détectées: {len(interfaces)}\n\n"
            
            for i, (iface, name) in enumerate(zip(interfaces, readable_names.values()), 1):
                info += f"{i}. {name}\n"
                info += f"   Identifiant technique: {iface}\n\n"
                
            # Interface par défaut
            default_iface = conf.iface if SCAPY_AVAILABLE else "Non disponible"
            info += f"🎯 Interface par défaut Scapy: {default_iface}\n\n"
            
            # Informations système
            info += "💻 SYSTÈME\n"
            info += "-" * 20 + "\n"
            info += f"OS: {platform.system()} {platform.release()}\n"
            info += f"Python: {platform.python_version()}\n"
            info += f"Scapy: {'Disponible' if SCAPY_AVAILABLE else 'Non disponible'}\n"
            
        except Exception as e:
            info += f"❌ Erreur lors de la récupération des informations: {e}\n"
        
        self.network_info_text.insert("0.0", info)
    
    def check_environment(self):
        """Vérifier l'environnement et les permissions"""
        if not SCAPY_AVAILABLE:
            self.log_message("❌ ERREUR: Scapy n'est pas installé!", "error")
            self.log_message("💡 Installez avec: pip install scapy", "info")
            self.start_button.configure(state="disabled")
            return
        
        # Charger les interfaces même sans privilèges admin
        self.load_interfaces()
        
        # Vérifier les permissions
        if not self.permission_manager.is_admin():
            self.log_message("⚠️ ATTENTION: Privilèges administrateur requis", "warning")
            self.show_permission_dialog()
        else:
            self.log_message("✅ Privilèges administrateur détectés", "success")
            
            # Test supplémentaire pour les raw sockets
            if not self.permission_manager.check_raw_socket_permission():
                self.log_message("⚠️ Problème d'accès aux raw sockets", "warning")
                if platform.system() == "Linux":
                    self.suggest_linux_setup()
        
        # Mettre à jour l'indicateur de permissions
        self.update_permission_indicator()
    
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
    
    def start_monitoring(self):
        """Démarrer la surveillance DHCP avec gestion d'erreurs améliorée"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Erreur", "Scapy n'est pas disponible!")
            return
            
        gateway = self.gateway_ip.get().strip()
        if not self.validate_ip(gateway):
            messagebox.showerror("Erreur", "Veuillez entrer une adresse IP de gateway valide!")
            return
            
        # Récupérer la valeur sélectionnée dans la combobox
        selected_value = self.selected_interface.get()
        if not selected_value:
            messagebox.showerror("Erreur", "Veuillez sélectionner une interface réseau!")
            return
            
        # Obtenir le nom réel de l'interface à partir de la valeur sélectionnée
        if hasattr(self, 'interface_mapping') and selected_value in self.interface_mapping:
            interface = self.interface_mapping[selected_value]
        else:
            # Si pas de mapping (ancienne méthode ou cas particulier), utiliser la valeur directement
            interface = selected_value
        
        # Vérification des permissions avant de commencer
        if not self.permission_manager.is_admin():
            result = messagebox.askyesno("Permissions insuffisantes", 
                                       "Vous n'avez pas les privilèges administrateur.\n"
                                       "La capture peut échouer.\n\n"
                                       "Continuer quand même?")
            if not result:
                return
            
        self.is_monitoring = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_label.configure(text="🔄 Capture en cours...")
        
        self.log_message("🚀 Démarrage de la capture DHCP", "success")
        self.log_message(f"🌐 Gateway: {gateway}")
        
        # Afficher à la fois le nom technique et le nom lisible de l'interface
        self.log_message(f"🔗 Interface technique: {interface}", "info")
        if selected_value != interface:
            self.log_message(f"   └─ Nom convivial: {selected_value}", "info")
            
        self.log_message("🎯 Surveillance des requêtes avec option 50 activée")
        
        # Message de filtre approprié selon le système
        if platform.system() == "Windows":
            self.log_message(f"🔍 Filtre BPF: udp (filtre permissif pour Windows)", "info")
        else:
            self.log_message(f"🔍 Filtre BPF: udp and (port 67 or port 68)", "info")
        
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
            
            # Configuration spécifique pour Windows
            if platform.system() == "Windows":
                self.log_message("🔧 Configuration Windows détectée", "info")
                conf.sniff_promisc = True  # Mode promiscuité
                
                # Essayer un filtre plus simple sur Windows qui peut être plus fiable
                self.log_message("🔄 Utilisation d'un filtre plus permissif pour Windows", "info")
                filter_expr = "udp"  # Capturer tous les paquets UDP
            else:
                # Filtre standard pour les autres OS
                filter_expr = "udp and (port 67 or port 68)"
                
            # Utilisation de la même configuration que dans dhcpboot.py
            self.log_message(f"🔍 Filtre utilisé: {filter_expr}", "info")
            sniff(filter=filter_expr,
                  prn=self.dhcp_packet_handler,
                  store=0,
                  iface=interface,
                  stop_filter=lambda x: not self.is_monitoring)
                  
        except PermissionError as e:
            self.log_message(f"❌ Erreur de permissions: {e}", "error")
            self.log_message("💡 Solution: Redémarrer en tant qu'administrateur", "info")
            self.message_queue.put(('permission_error', f"Erreur de permissions: {e}"))
        except OSError as e:
            self.log_message(f"❌ Erreur système: {e}", "error")
            if "Operation not permitted" in str(e):
                self.log_message("💡 Vérifiez les privilèges administrateur", "info")
            elif "No such device" in str(e):
                self.log_message("💡 Interface réseau introuvable", "info")
            self.message_queue.put(('os_error', f"Erreur système: {e}"))
        except Exception as e:
            self.log_message(f"❌ Erreur de capture: {e}", "error")
            self.log_message(f"📝 Type d'erreur: {type(e).__name__}", "info")
            # Afficher le traceback pour faciliter le débogage
            import traceback
            self.log_message(f"Traceback: {traceback.format_exc()}", "error")
        finally:
            if self.is_monitoring:
                self.message_queue.put(('capture_ended', "Capture terminée de manière inattendue"))
            
    def stop_monitoring(self):
        """Arrêter la surveillance avec nettoyage complet"""
        self.is_monitoring = False
        
        # Nettoyer les callbacks programmés
        if self.queue_check_id:
            try:
                self.after_cancel(self.queue_check_id)
                self.queue_check_id = None
            except (tk.TclError, ValueError):
                pass
                
        if self.graph_update_id:
            try:
                self.after_cancel(self.graph_update_id)
                self.graph_update_id = None
            except (tk.TclError, ValueError):
                pass
        
        # Attendre que le thread se termine
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2.0)
        
        # Mettre à jour l'interface seulement si pas en fermeture
        if not self.is_closing:
            try:
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.status_label.configure(text="⏹️ Arrêté")
                self.log_message("🛑 Capture arrêtée", "info")
            except (tk.TclError, AttributeError):
                pass
    
    def clear_logs(self):
        """Effacer tous les logs"""
        self.log_text.delete("0.0", "end")
        self.option50_text.delete("0.0", "end")
        self.stats_text.delete("0.0", "end")
        self.stats = {'total_packets': 0, 'option50_packets': 0, 'dhcp_types': {}, 'gateway_packets': 0}
        self.log_message("🗑️ Logs effacés", "info")
    
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
        """Ajouter un message aux logs avec coloration avancée"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Déterminer les couleurs selon le type de message
        if "✅" in message or "OK" in message or "succès" in message.lower():
            color_type = "success"
        elif "❌" in message or "ERREUR" in message or "ÉCHEC" in message:
            color_type = "error"
        elif "⚠️" in message or "ATTENTION" in message or "WARNING" in message:
            color_type = "warning"
        elif "🎯" in message or "Option 50" in message:
            color_type = "option50"
        elif "🌐" in message or "GATEWAY" in message:
            color_type = "gateway"
        elif "💡" in message or "🔍" in message or "📡" in message:
            color_type = "info"
        else:
            color_type = msg_type
        
        # Formater avec coloration intelligente
        timestamp_part = f"[{timestamp}] "
        
        # Coloriser le message de manière intelligente
        colored_parts = colorize_log_message(message)
        
        # Ajouter à la queue pour traitement thread-safe
        self.message_queue.put(('log_advanced', timestamp_part, colored_parts, color_type))
        
    def log_option50(self, message):
        """Ajouter un message spécifiquement pour l'option 50 avec coloration avancée"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        timestamp_part = f"[{timestamp}] "
        
        # Coloriser le message de manière intelligente
        colored_parts = colorize_log_message(message)
        
        self.message_queue.put(('option50_advanced', timestamp_part, colored_parts, "option50"))
    
    def update_stats(self, packet_info):
        """Mettre à jour les statistiques"""
        if packet_info:  # Vérifier que packet_info n'est pas None
            self.message_queue.put(('stats', packet_info))
        
    def check_queue(self):
        """Vérifier la queue des messages de manière thread-safe avec coloration avancée"""
        # Vérifier si l'application est en cours de fermeture
        if self.is_closing:
            return
            
        try:
            while True:
                message_data = self.message_queue.get_nowait()
                msg_type = message_data[0]
                
                if msg_type == 'log':
                    _, timestamp_part, message, color_type = message_data
                    # Insérer avec couleur simple (rétrocompatibilité)
                    self.log_text.append_colored(timestamp_part, "timestamp")
                    self.log_text.append_colored(f"{message}\n", color_type)
                    
                elif msg_type == 'log_advanced':
                    _, timestamp_part, colored_parts, base_color = message_data
                    # Insérer le timestamp
                    self.log_text.append_colored(timestamp_part, "timestamp")
                    # Insérer le message avec coloration multiple
                    self.log_text.append_mixed_colored(colored_parts)
                    self.log_text.append_colored("\n", "default")
                    
                elif msg_type == 'option50':
                    _, timestamp_part, message, color_type = message_data
                    # Insérer avec couleur simple dans l'onglet Option 50
                    self.option50_text.append_colored(timestamp_part, "timestamp")
                    self.option50_text.append_colored(f"{message}\n", color_type)
                    
                elif msg_type == 'option50_advanced':
                    _, timestamp_part, colored_parts, base_color = message_data
                    # Insérer le timestamp
                    self.option50_text.append_colored(timestamp_part, "timestamp")
                    # Insérer le message avec coloration multiple
                    self.option50_text.append_mixed_colored(colored_parts)
                    self.option50_text.append_colored("\n", "default")
                    
                elif msg_type == 'stats':
                    if len(message_data) > 1:
                        self.process_stats(message_data[1])
                    else:
                        self.log_message("⚠️ Erreur: données de statistiques manquantes", "warning")
                
                elif msg_type == 'permission_error' or msg_type == 'os_error':
                    # Afficher une notification pour les erreurs importantes
                    self.status_label.configure(text=f"⚠️ Erreur: {message_data[1]}")
                    
                elif msg_type == 'capture_ended':
                    self.status_label.configure(text=f"⚠️ {message_data[1]}")
                    self.stop_monitoring()
                    
        except queue.Empty:
            pass
        except Exception as e:
            # En cas d'erreur, ne pas arrêter la vérification
            if not self.is_closing:
                print(f"Erreur dans check_queue: {e}")
        
        # Programmer la prochaine vérification seulement si pas en fermeture
        if not self.is_closing:
            try:
                self.queue_check_id = self.after(100, self.check_queue)
            except tk.TclError:
                # Widget détruit, arrêter les callbacks
                pass
    
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
            
        self.stats_text.delete("0.0", "end")
        self.stats_text.insert("0.0", stats_text)
        
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
                elif opt_code == "vendor_class_id":
                    parsed['vendor'] = opt_value
        return parsed
        
    def get_dhcp_message_type(self, msg_type):
        """Convertir le type de message DHCP"""
        types = {
            1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
            5: "ACK", 6: "NACK", 7: "RELEASE", 8: "INFORM"
        }
        return types.get(msg_type, f"TYPE_{msg_type}")
        
    def dhcp_packet_handler(self, packet):
        """Gestionnaire de paquets DHCP avec coloration avancée"""
        try:
            # Vérifier que c'est bien un paquet DHCP
            if packet.haslayer(DHCP) and packet.haslayer(IP) and packet.haslayer(UDP):
                # Si nous utilisons un filtre permissif sur Windows, filtrons manuellement
                if platform.system() == "Windows" and not (
                    packet[UDP].sport in (67, 68) or packet[UDP].dport in (67, 68)
                ):
                    return  # Ignorer ce paquet s'il n'utilise pas les ports DHCP
                
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                mac_src = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
                mac_dst = packet[Ether].dst if packet.haslayer(Ether) else "Unknown"
                
                dhcp_options = self.parse_dhcp_options(packet[DHCP].options)
                
                # Variable pour tracker Option 50
                has_option50 = 'requested_ip' in dhcp_options
                
                # Mettre à jour les graphiques
                if hasattr(self, 'network_graphs'):
                    self.network_graphs.add_packet_data(is_option50=has_option50)
                    # Mettre à jour le graphique périodiquement
                    if self.stats['total_packets'] % 5 == 0:  # Toutes les 5 captures
                        self.network_graphs.update_graphs()
                
                # Informations du paquet pour les stats
                packet_info = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'is_gateway': src_ip == self.gateway_ip.get() or dst_ip == self.gateway_ip.get()
                }
                
                # Log principal avec coloration améliorée
                log_msg = f"📡 BOOTP/DHCP Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}"
                self.log_message(log_msg, "info")
                
                # MAC avec couleur spécifique
                mac_msg = f"  └─ 🔗 MAC: {mac_src} → {mac_dst}"
                self.log_message(mac_msg, "info")
                
                if 'msg_type' in dhcp_options:
                    msg_type_str = self.get_dhcp_message_type(dhcp_options['msg_type'])
                    msg_type_msg = f"  └─ 📋 Message Type: {msg_type_str} ({dhcp_options['msg_type']})"
                    self.log_message(msg_type_msg, "info")
                    packet_info['msg_type'] = dhcp_options['msg_type']
                    
                    # Focus sur l'option 50 avec couleur spéciale et IP en jaune vif
                    if 'requested_ip' in dhcp_options:
                        requested_ip = dhcp_options['requested_ip']
                        
                        # Message coloré pour Option 50 avec IP en surbrillance
                        option50_parts = [
                            ("  └─ 🎯 Option 50 - Requested IP: ", "option50"),
                            (f"{requested_ip}", "ip_address")
                        ]
                        # Créer un message coloré personnalisé
                        option50_msg = f"  └─ 🎯 Option 50 - Requested IP: {requested_ip}"
                        self.log_message(option50_msg, "option50")
                        
                        # Pour l'onglet Option 50, message simplifié
                        simple_option50 = f"🎯 Option 50: {requested_ip} | {src_ip} → {dst_ip} | {msg_type_str}"
                        self.log_option50(simple_option50)
                        
                        packet_info['option50'] = requested_ip
                        
                        # Vérification gateway avec couleur spéciale
                        if packet_info['is_gateway']:
                            self.log_message("  └─ 🌐 GATEWAY ACTIVITY DETECTED!", "gateway")
                        
                        # Analyse selon le type de message avec couleurs appropriées
                        if dhcp_options['msg_type'] == 3:  # REQUEST
                            analysis_msg = f"  └─ 📤 Client demande l'IP {requested_ip}"
                            self.log_message(analysis_msg, "info")
                        elif dhcp_options['msg_type'] == 5:  # ACK
                            success_msg = f"  └─ ✅ Serveur confirme l'attribution de {requested_ip}"
                            self.log_message(success_msg, "success")
                        elif dhcp_options['msg_type'] == 6:  # NACK
                            error_msg = f"  └─ ❌ Serveur refuse l'attribution de {requested_ip}"
                            self.log_message(error_msg, "error")
                            
                    # Autres informations avec couleurs spécifiques
                    if 'server_id' in dhcp_options:
                        server_msg = f"  └─ 🖥️ Server ID: {dhcp_options['server_id']}"
                        self.log_message(server_msg, "server_id")
                        
                    if 'hostname' in dhcp_options:
                        hostname_msg = f"  └─ 🏷️ Hostname: {dhcp_options['hostname']}"
                        self.log_message(hostname_msg, "hostname")
                        
                    if 'vendor' in dhcp_options:
                        vendor_msg = f"  └─ 🏢 Vendor: {dhcp_options['vendor']}"
                        self.log_message(vendor_msg, "vendor")
                        
                # Séparateur visuel avec couleur
                separator = "-" * 60
                self.log_message(separator, "info")
                        
                # Mettre à jour les statistiques
                self.update_stats(packet_info)
                
        except Exception as e:
            self.log_message(f"❌ Erreur lors du traitement du paquet: {e}", "error")
    
    def reset_graphs(self):
        """Réinitialiser les graphiques"""
        if hasattr(self, 'network_graphs'):
            self.network_graphs.reset_data()
            self.network_graphs.update_graphs()
            self.log_message("📈 Graphiques réinitialisés", "info")
    
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
            interfaces, _ = get_readable_interfaces() if SCAPY_AVAILABLE else ([], {})
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
                self.log_message("  • Utiliser sudo", "info")
                
        if not SCAPY_AVAILABLE:
            self.log_message("  • Installer Scapy: pip install scapy", "info")
    
    def load_interfaces(self):
        """Charger les interfaces réseau disponibles"""
        try:
            if not SCAPY_AVAILABLE:
                self.log_message("❌ Scapy non disponible pour lister les interfaces", "error")
                # Ajouter une interface par défaut pour pouvoir tester
                self.interface_combo.configure(values=["Aucune interface disponible"])
                self.interface_combo.set("Aucune interface disponible")
                return
                
            self.log_message("🔍 Chargement des interfaces réseau...", "info")
            interfaces, readable_names = get_readable_interfaces()
            
            if not interfaces:
                self.log_message("⚠️ Aucune interface réseau trouvée", "warning")
                self.interface_combo.configure(values=["Aucune interface disponible"])
                self.interface_combo.set("Aucune interface disponible")
                return
            
            # Ajouter l'interface par défaut de Scapy en premier
            default_iface = conf.iface
            self.log_message(f"✅ Interface par défaut détectée: {default_iface}", "info")
            
            # Si on est sur Windows, afficher le nom lisible de l'interface par défaut
            if platform.system() == "Windows" and default_iface in readable_names:
                self.log_message(f"   └─ {readable_names[default_iface]}", "info")
            
            # S'assurer que l'interface par défaut est en premier dans la liste
            if default_iface in interfaces:
                interfaces.remove(default_iface)
                interfaces.insert(0, default_iface)
            
            # Créer une liste de valeurs pour la combobox avec les noms lisibles
            combo_values = []
            for iface in interfaces:
                if platform.system() == "Windows" and iface in readable_names:
                    # On n'affiche que le nom lisible dans la combobox
                    combo_values.append(readable_names[iface])
                else:
                    combo_values.append(iface)
            
            # Stocker la correspondance entre les valeurs de la combobox et les interfaces réelles
            self.interface_mapping = {}
            for i, value in enumerate(combo_values):
                self.interface_mapping[value] = interfaces[i]
                
            # Mettre à jour la combobox
            self.interface_combo.configure(values=combo_values)
            if combo_values:
                self.interface_combo.set(combo_values[0])
                self.selected_interface.set(combo_values[0])
                self.log_message(f"✅ {len(interfaces)} interfaces chargées", "success")
                
                # Afficher la liste des interfaces chargées
                for i, (display_name, real_name) in enumerate(zip(combo_values, interfaces)):
                    if display_name != real_name:
                        self.log_message(f"   {i+1}. {display_name} → {real_name}", "info")
                    else:
                        self.log_message(f"   {i+1}. {display_name}", "info")
            else:
                self.log_message("⚠️ Aucune interface réseau trouvée", "warning")
                
        except Exception as e:
            self.log_message(f"❌ Erreur lors du chargement des interfaces: {e}", "error")
            import traceback
            self.log_message(f"Détails: {traceback.format_exc()}", "error")
            # Interface de secours
            self.interface_combo.configure(values=["Erreur de chargement"])
            self.interface_combo.set("Erreur de chargement")

    def on_closing(self):
        """Gérer la fermeture de la fenêtre"""
        self.is_closing = True
        self.stop_monitoring()
        
        # Nettoyer tous les callbacks restants
        try:
            # Vider la queue des messages
            while not self.message_queue.empty():
                try:
                    self.message_queue.get_nowait()
                except queue.Empty:
                    break
        except:
            pass
            
        # Fermer la fenêtre
        try:
            self.quit()
            self.destroy()
        except:
            pass

def main():
    """Fonction principale avec gestion complète des erreurs"""
    
    # Créer l'application
    app = DHCPMonitorGUI()
    
    # Mettre à jour l'indicateur de permissions
    app.update_permission_indicator()
    
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app.stop_monitoring()
    except Exception as e:
        messagebox.showerror("Erreur critique", f"Erreur inattendue: {e}")

def show_about():
    """Afficher les informations sur l'application"""
    about_text = """🔍 DHCP Monitor - Option 50 Tracker

Version: 4.0 (Interface CustomTkinter moderne)
Développé avec ❤️ par Assistant IA
Licence: Open Source

✨ Fonctionnalités:
• Interface graphique ultra-moderne avec CustomTkinter
• Système de thèmes automatique (Clair/Sombre/Système)
• Capture en temps réel des paquets DHCP
• Surveillance spécifique de l'option 50
• Gestion avancée des permissions
• Statistiques détaillées en temps réel
• Support multi-plateforme (Windows/Linux)
• Noms d'interfaces réseau conviviaux
• Design moderne et responsive

🔧 Permissions requises:
• Capture de paquets réseau (raw sockets)
• Accès aux interfaces réseau
• Privilèges administrateur/root

💡 Support:
• Windows: Exécuter en tant qu'administrateur
• Linux: sudo ou configuration setcap

🎨 Interface moderne avec CustomTkinter"""
    
    messagebox.showinfo("À propos", about_text)

if __name__ == "__main__":
    main()
