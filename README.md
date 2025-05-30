# 🔍 DHCP Monitor - Option 50 Tracker

Un outil avancé de surveillance DHCP avec focus sur l'Option 50 (Requested IP Address). Disponible en **deux modes** : CLI et GUI.

## 📋 Modes d'Utilisation

### 🖥️ **Executable** - `/dist/monitor.exe`
**Executable Windows** pour une surveillance rapide et légère et intuitive.

### 🖥️ **Mode CLI** - `dhcpboot.py`
**Interface en ligne de commande** pour une surveillance rapide et légère.

```bash
python dhcpboot.py
```

**Fonctionnalités CLI :**
- ✅ Surveillance DHCP en temps réel
- ✅ Détection automatique de l'Option 50
- ✅ Logs colorés dans le terminal
- ✅ Performance optimisée
- ✅ Idéal pour serveurs et scripts

### 🎨 **Mode GUI** - `monitor.py`
**Interface graphique moderne** avec visualisations avancées.

```bash
python monitor.py
```

**Fonctionnalités GUI :**
- 🚀 **Interface CustomTkinter ultra-moderne**
- 🎨 **Logs colorés avec syntaxe highlighting**
- 📈 **Graphiques temps réel style Wireshark**
- 🌐 **Gestion intelligente des interfaces réseau**
- 🎯 **Onglets spécialisés** (Logs, Option 50, Stats, Graphiques, Réseau)
- 🎨 **Système de thèmes** (Clair/Sombre/Système)
- 🔧 **Outils de diagnostic intégrés**
- 📊 **Statistiques détaillées en temps réel**

## 🚀 Installation

### Prérequis
- Python 3.8+
- Privilèges administrateur (pour capture réseau)
- Windows/Linux/macOS

### Installation des dépendances
```bash
pip install -r requirements.txt
```

### Dépendances principales
- **scapy** : Capture et analyse de paquets
- **customtkinter** : Interface graphique moderne
- **matplotlib** : Graphiques temps réel
- **darkdetect** : Détection automatique du thème système

## 🎯 Qu'est-ce que l'Option 50 DHCP ?

L'**Option 50 (Requested IP Address)** est un champ spécial dans les requêtes DHCP qui permet :
- 🔄 **Renouvellement d'adresse** : Client demande la même IP
- 🎯 **IP préférée** : Client suggère une adresse spécifique
- 🔍 **Analyse de comportement** : Suivi des demandes clients

## 📊 Captures d'écran

### Mode CLI (`dhcpboot.py`)
```
[14:32:15.123] 🚀 Démarrage de la capture DHCP
[14:32:15.456] 📡 DHCP Packet: 192.168.1.100:68 → 192.168.1.1:67
[14:32:15.457]   └─ 🎯 Option 50 - Requested IP: 192.168.1.100
[14:32:15.458]   └─ 📋 Message Type: REQUEST (3)
```

### Mode GUI (`monitor.py`)
- Interface moderne avec sidebar et onglets
- Graphiques temps réel du trafic DHCP
- Coloration syntaxique avancée
- Gestion visuelle des interfaces réseau

## 🛠️ Utilisation Avancée

### Mode CLI - Surveillance automatisée
```bash
# Surveillance continue avec redirection
python dhcpboot.py > dhcp_monitoring.log 2>&1

# Avec interface spécifique (Linux)
sudo python dhcpboot.py --interface eth0
```

### Mode GUI - Analyse interactive
1. **Lancez l'interface** : `python monitor.py`
2. **Sélectionnez l'interface** réseau dans la sidebar
3. **Configurez la Gateway IP** si nécessaire
4. **Démarrez la capture** avec le bouton 🚀
5. **Visualisez les données** dans les différents onglets :
   - **📋 Tous les logs** : Vue d'ensemble colorée
   - **🎯 Option 50** : Focus sur les requêtes spécifiques
   - **📊 Statistiques** : Métriques en temps réel
   - **📈 Graphiques** : Visualisation style Wireshark
   - **🌐 Réseau** : Informations sur les interfaces

## 🔧 Configuration

### Permissions requises

**Windows :**
```bash
# Lancer en tant qu'administrateur
# Clic droit → "Exécuter en tant qu'administrateur"
```

**Linux :**
```bash
# Méthode 1: sudo
sudo python monitor.py

# Méthode 2: setcap (recommandé)
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3
python monitor.py
```

### Interfaces réseau

L'application détecte automatiquement les interfaces et affiche des **noms conviviaux** :
- Windows : "Ethernet", "Wi-Fi", "Bluetooth"
- Linux : "eth0", "wlan0", "lo"

## 🎨 Fonctionnalités Visuelles

### Coloration des logs
- 🟢 **Succès** : Confirmations DHCP ACK
- 🔴 **Erreurs** : DHCP NACK, erreurs système
- 🟠 **Avertissements** : Permissions, configurations
- 🔵 **Informations** : Paquets généraux
- 🟣 **Option 50** : Requêtes d'adresses spécifiques
- 🟡 **Gateway** : Activité de la passerelle

### Graphiques temps réel
- **Courbe DHCP totale** : Trafic global
- **Courbe Option 50** : Requêtes spécifiques
- **Mise à jour automatique** : Toutes les 5 captures
- **Style professionnel** : Inspiré de Wireshark

## 🚨 Dépannage

### Problèmes courants

**"Scapy non disponible"**
```bash
pip install scapy
```

**"Privilèges insuffisants"**
- Windows : Exécuter en tant qu'administrateur
- Linux : Utiliser `sudo` ou configurer `setcap`

**"Aucune interface trouvée"**
- Vérifier que les interfaces réseau sont actives
- Redémarrer l'application
- Utiliser le bouton "🔄 Actualiser"

**Interface ne répond pas**
- Vérifier les permissions réseau
- Tester avec `dhcpboot.py` en CLI d'abord
- Consulter l'onglet "🧪 Tester permissions"

## 📈 Statistiques

L'application fournit des métriques détaillées :
- **Total paquets** DHCP capturés
- **Paquets Option 50** spécifiques
- **Types de messages** (DISCOVER, OFFER, REQUEST, ACK, etc.)
- **Activité Gateway** détectée
- **Graphiques temporels** en temps réel

## 🤝 Contribution

Les contributions sont les bienvenues ! Domaines d'amélioration :
- Support d'autres options DHCP
- Filtres avancés
- Export des données
- Plugins d'analyse
- Documentation multilingue

## 📄 Licence

Projet open source sous licence MIT.

## 🔗 Liens utiles

- [RFC 2132 - DHCP Options](https://tools.ietf.org/html/rfc2132)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)

---

*Développé avec ❤️ pour la communauté réseau*
