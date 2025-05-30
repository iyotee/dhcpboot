#!/bin/bash

echo "🔧 Script de résolution des privilèges pour DHCP Monitor"
echo "=================================================="

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages colorés
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 1. Résoudre le problème d'affichage X11
echo -e "\n${BLUE}1. Configuration de l'affichage X11${NC}"
print_status "Configuration de DISPLAY pour X11 forwarding..."

# Exporter la variable DISPLAY
export DISPLAY=:0.0

# Vérifier si on est en SSH et configurer X11 forwarding
if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
    print_warning "Connexion SSH détectée"
    print_status "Pour X11 forwarding, utilisez: ssh -X user@host"
    
    # Essayer de détecter le bon DISPLAY
    if [ -f /tmp/.X11-unix/X0 ]; then
        export DISPLAY=:0
        print_success "DISPLAY configuré sur :0"
    elif [ -f /tmp/.X11-unix/X10 ]; then
        export DISPLAY=:10.0
        print_success "DISPLAY configuré sur :10.0"
    fi
else
    print_success "Session locale détectée"
fi

# 2. Installer les dépendances manquantes
echo -e "\n${BLUE}2. Installation des dépendances${NC}"
print_status "Vérification et installation des paquets requis..."

# Mettre à jour les paquets
sudo apt update

# Installer les dépendances Python et réseau
sudo apt install -y python3-pip python3-tk python3-dev libpcap-dev

# Installer Scapy avec pip
print_status "Installation de Scapy..."
pip3 install --user scapy

# 3. Résoudre le problème setcap
echo -e "\n${BLUE}3. Configuration des privilèges réseau${NC}"

# Trouver le bon chemin de Python
PYTHON_PATH=$(which python3)
print_status "Chemin Python détecté: $PYTHON_PATH"

# Vérifier si setcap est disponible
if ! command -v setcap &> /dev/null; then
    print_error "setcap n'est pas installé"
    print_status "Installation de libcap2-bin..."
    sudo apt install -y libcap2-bin
fi

# Méthode 1: setcap sur l'exécutable Python
print_status "Tentative de configuration avec setcap..."
if sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_PATH" 2>/dev/null; then
    print_success "setcap configuré avec succès sur $PYTHON_PATH"
else
    print_warning "setcap a échoué, tentative d'une approche alternative..."
    
    # Méthode 2: Créer un wrapper script
    print_status "Création d'un script wrapper..."
    cat > /tmp/dhcp_wrapper.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
exec(open('monitor.py').read())
EOF
    
    chmod +x /tmp/dhcp_wrapper.py
    sudo cp /tmp/dhcp_wrapper.py /usr/local/bin/dhcp_monitor
    
    if sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/dhcp_monitor 2>/dev/null; then
        print_success "Wrapper script créé avec setcap"
    else
        print_warning "setcap continue d'échouer, utilisation des méthodes alternatives..."
    fi
fi

# 4. Configuration alternative avec sudo
echo -e "\n${BLUE}4. Configuration des règles sudo (alternative)${NC}"
print_status "Création d'une règle sudo spécifique..."

# Créer une règle sudo pour permettre l'exécution sans mot de passe
SUDO_RULE="%sudo ALL=(ALL) NOPASSWD: $(which python3) */monitor.py"
echo "$SUDO_RULE" | sudo tee /etc/sudoers.d/dhcp-monitor > /dev/null

if [ $? -eq 0 ]; then
    print_success "Règle sudo créée pour DHCP Monitor"
else
    print_warning "Impossible de créer la règle sudo"
fi

# 5. Test des privilèges
echo -e "\n${BLUE}5. Test des privilèges${NC}"
print_status "Test de l'accès aux raw sockets..."

# Test simple de création de raw socket
python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.close()
    print('✅ Raw sockets: OK')
except PermissionError:
    print('❌ Raw sockets: ÉCHEC - Privilèges insuffisants')
except Exception as e:
    print(f'⚠️  Raw sockets: Test incomplet - {e}')
"

# Test Scapy
python3 -c "
try:
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print(f'✅ Scapy: OK - {len(interfaces)} interfaces détectées')
except ImportError:
    print('❌ Scapy: Module non trouvé')
except Exception as e:
    print(f'⚠️  Scapy: Erreur - {e}')
"

# 6. Scripts de lancement
echo -e "\n${BLUE}6. Création des scripts de lancement${NC}"

# Script de lancement avec sudo
cat > launch_dhcp_sudo.sh << 'EOF'
#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec sudo..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
sudo -E python3 monitor.py
EOF

# Script de lancement avec setcap
cat > launch_dhcp_setcap.sh << 'EOF'
#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec setcap..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
python3 monitor.py
EOF

# Script de lancement du wrapper
cat > launch_dhcp_wrapper.sh << 'EOF'
#!/bin/bash
echo "🚀 Lancement DHCP Monitor avec wrapper..."
export DISPLAY=${DISPLAY:-:0}
cd "$(dirname "$0")"
/usr/local/bin/dhcp_monitor
EOF

chmod +x launch_dhcp_*.sh

print_success "Scripts de lancement créés:"
print_status "  - launch_dhcp_sudo.sh (utilise sudo)"
print_status "  - launch_dhcp_setcap.sh (utilise setcap)"
print_status "  - launch_dhcp_wrapper.sh (utilise wrapper)"

# 7. Instructions finales
echo -e "\n${GREEN}✅ Configuration terminée!${NC}"
echo "=================================================="
print_status "Méthodes de lancement disponibles:"
echo ""
print_status "1. Avec sudo (recommandé):"
echo "   ./launch_dhcp_sudo.sh"
echo ""
print_status "2. Avec setcap (si configuré):"
echo "   ./launch_dhcp_setcap.sh"
echo ""
print_status "3. Directement avec sudo:"
echo "   sudo python3 monitor.py"
echo ""
print_status "4. Pour SSH avec X11:"
echo "   ssh -X user@host"
echo "   export DISPLAY=:10.0"
echo "   sudo -E python3 monitor.py"
echo ""

# Vérification finale
print_status "Vérification de la configuration..."
if getcap "$PYTHON_PATH" | grep -q "cap_net_raw"; then
    print_success "setcap configuré correctement"
elif [ -f /usr/local/bin/dhcp_monitor ]; then
    print_success "Script wrapper disponible"
else
    print_warning "Utilisez sudo pour lancer l'application"
fi

print_status "Configuration des privilèges terminée!"
