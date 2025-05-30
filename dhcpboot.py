#!/usr/bin/env python3
import re
from scapy.all import sniff, DHCP, IP, Ether, UDP, conf
from datetime import datetime

# Fonction pour valider une adresse IP
def validate_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(pattern, ip) is not None and all(0 <= int(octet) <= 255 for octet in ip.split("."))

# Demande à l'utilisateur d'entrer l'adresse IP de la gateway
while True:
    gateway_ip = input("Entrez l'adresse IP de la gateway de votre réseau : ")
    if validate_ip(gateway_ip):
        break
    print("⛔ Erreur : Veuillez entrer une adresse IP valide (exemple : 192.168.1.1)")

# Détection automatique de l'interface réseau
iface = conf.iface
print(f"🔍 Interface détectée : {iface}")
print(f"📡 Capture en cours sur l'interface '{iface}' (filtre BOOTP/DHCP)...")
print(f"🎯 Surveillance des requêtes DHCP avec option 50 (Requested IP Address)")
print(f"🌐 Gateway configurée : {gateway_ip}")
print("-" * 80)

def parse_dhcp_options(options):
    """Parse les options DHCP et retourne un dictionnaire"""
    parsed = {}
    for option in options:
        if isinstance(option, tuple) and len(option) == 2:
            opt_code, opt_value = option
            if opt_code == "message-type":
                parsed['msg_type'] = opt_value
            elif opt_code == "requested_addr":  # Option 50
                parsed['requested_ip'] = opt_value
            elif opt_code == "server_id":
                parsed['server_id'] = opt_value
            elif opt_code == "hostname":
                parsed['hostname'] = opt_value
            elif opt_code == "vendor_class_id":
                parsed['vendor'] = opt_value
    return parsed

def get_dhcp_message_type(msg_type):
    """Convertit le type de message DHCP en texte"""
    types = {
        1: "DISCOVER",
        2: "OFFER", 
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NACK",
        7: "RELEASE",
        8: "INFORM"
    }
    return types.get(msg_type, f"TYPE_{msg_type}")

def dhcp_monitor_enhanced(packet):
    """Fonction de monitoring DHCP inspirée de la capture Wireshark"""
    if packet.haslayer(DHCP) and packet.haslayer(IP) and packet.haslayer(UDP):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        mac_src = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
        mac_dst = packet[Ether].dst if packet.haslayer(Ether) else "Unknown"
        
        # Parse des options DHCP
        dhcp_options = parse_dhcp_options(packet[DHCP].options)
        
        # Affichage similaire à Wireshark
        print(f"[{timestamp}] BOOTP/DHCP Packet")
        print(f"  └─ {src_ip}:{src_port} → {dst_ip}:{dst_port}")
        print(f"  └─ MAC: {mac_src} → {mac_dst}")
        
        if 'msg_type' in dhcp_options:
            msg_type_str = get_dhcp_message_type(dhcp_options['msg_type'])
            print(f"  └─ Message Type: {msg_type_str} ({dhcp_options['msg_type']})")
            
            # Focus sur l'option 50 (Requested IP Address)
            if 'requested_ip' in dhcp_options:
                requested_ip = dhcp_options['requested_ip']
                print(f"  └─ 🎯 Option 50 - Requested IP Address: {requested_ip}")
                
                # Vérification si c'est lié à notre gateway
                if src_ip == gateway_ip or dst_ip == gateway_ip:
                    print(f"  └─ 🌐 GATEWAY ACTIVITY DETECTED!")
                    
                # Analyse selon le type de message
                if dhcp_options['msg_type'] == 3:  # REQUEST
                    print(f"  └─ 📤 Client demande l'IP {requested_ip}")
                elif dhcp_options['msg_type'] == 5:  # ACK
                    print(f"  └─ ✅ Serveur confirme l'attribution de {requested_ip}")
                elif dhcp_options['msg_type'] == 6:  # NACK
                    print(f"  └─ ❌ Serveur refuse l'attribution de {requested_ip}")
                    
            # Autres informations utiles
            if 'server_id' in dhcp_options:
                print(f"  └─ Server ID: {dhcp_options['server_id']}")
            if 'hostname' in dhcp_options:
                print(f"  └─ Hostname: {dhcp_options['hostname']}")
            if 'vendor' in dhcp_options:
                print(f"  └─ Vendor: {dhcp_options['vendor']}")
                
        print("-" * 50)

# Capture avec filtre BOOTP (comme dans Wireshark)
try:
    print("🚀 Démarrage de la capture DHCP (Ctrl+C pour arrêter)...\n")
    # Utilisation du même filtre que Wireshark : bootp
    sniff(filter="udp and (port 67 or port 68)", 
          prn=dhcp_monitor_enhanced, 
          store=0, 
          iface=iface)
except KeyboardInterrupt:
    print("\n🛑 Capture arrêtée par l'utilisateur")
except Exception as e:
    print(f"⛔ Erreur critique : {e}")
    print("💡 Essayez d'exécuter le script en tant qu'administrateur/root")
