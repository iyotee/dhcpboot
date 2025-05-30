# 🔍 DHCP Monitor - Option 50 Tracker

Un script Python avancé pour surveiller et analyser le trafic DHCP en temps réel, avec un focus particulier sur l'option 50 (Requested IP Address). Inspiré des captures Wireshark pour une analyse réseau professionnelle.

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Exemples de sortie](#-exemples-de-sortie)
- [Options DHCP surveillées](#-options-dhcp-surveillées)
- [Dépannage](#-dépannage)
- [Contribution](#-contribution)
- [Licence](#-licence)

## ✨ Fonctionnalités

- 🎯 **Surveillance ciblée de l'option 50** : Capture et analyse les requêtes d'adresses IP spécifiques
- 🌐 **Détection d'activité Gateway** : Identification automatique des paquets impliquant votre passerelle
- 📊 **Affichage type Wireshark** : Format de sortie professionnel avec timestamps et détails techniques
- 🔄 **Analyse en temps réel** : Monitoring continu du trafic DHCP/BOOTP
- 🏷️ **Parsing complet des options** : Analyse détaillée de toutes les options DHCP importantes
- 📱 **Auto-détection d'interface** : Sélection automatique de l'interface réseau active

## 🛠 Prérequis

- **Python 3.6+**
- **Privilèges administrateur/root** (requis pour la capture de paquets)
- **Système d'exploitation** : Linux, macOS, Windows (avec limitations)

### Dépendances Python

```bash
pip install scapy
```

## 📦 Installation

1. **Cloner le repository**
   ```bash
   git clone https://github.com/votre-username/dhcp-monitor-option50.git
   cd dhcp-monitor-option50
   ```

2. **Installer les dépendances**
   ```bash
   pip install -r requirements.txt
   ```

3. **Vérifier les permissions**
   ```bash
   # Linux/macOS
   sudo python dhcp_monitor.py
   
   # Windows (PowerShell en tant qu'administrateur)
   python dhcp_monitor.py
   ```

## 🚀 Utilisation

### Lancement basique

```bash
sudo python dhcp_monitor.py
```

### Exemple d'interaction

```
Entrez l'adresse IP de la gateway de votre réseau : 192.168.1.1
🔍 Interface détectée : eth0
📡 Capture en cours sur l'interface 'eth0' (filtre BOOTP/DHCP)...
🎯 Surveillance des requêtes DHCP avec option 50 (Requested IP Address)
🌐 Gateway configurée : 192.168.1.1
```

### Arrêter la capture

Utilisez `Ctrl+C` pour arrêter proprement la capture.

## 📊 Exemples de sortie

### Requête DHCP REQUEST avec Option 50

```
[14:32:15.742] BOOTP/DHCP Packet
  └─ 192.168.1.100:68 → 192.168.1.1:67
  └─ MAC: aa:bb:cc:dd:ee:ff → ff:ff:ff:ff:ff:ff
  └─ Message Type: REQUEST (3)
  └─ 🎯 Option 50 - Requested IP Address: 192.168.1.150
  └─ 📤 Client demande l'IP 192.168.1.150
  └─ Server ID: 192.168.1.1
  └─ Hostname: laptop-john
--------------------------------------------------
```

### Réponse DHCP ACK

```
[14:32:15.758] BOOTP/DHCP Packet
  └─ 192.168.1.1:67 → 192.168.1.100:68
  └─ MAC: 11:22:33:44:55:66 → aa:bb:cc:dd:ee:ff
  └─ Message Type: ACK (5)
  └─ 🎯 Option 50 - Requested IP Address: 192.168.1.150
  └─ ✅ Serveur confirme l'attribution de 192.168.1.150
  └─ 🌐 GATEWAY ACTIVITY DETECTED!
  └─ Server ID: 192.168.1.1
--------------------------------------------------
```

## 📋 Options DHCP surveillées

| Option | Code | Description | Symbole |
|--------|------|-------------|---------|
| Message Type | 53 | Type de message DHCP | 📋 |
| Requested IP | 50 | IP demandée par le client | 🎯 |
| Server ID | 54 | Identifiant du serveur DHCP | 🖥️ |
| Hostname | 12 | Nom d'hôte du client | 🏷️ |
| Vendor Class | 60 | Classe du fabricant | 🏭 |

### Types de messages DHCP

- **DISCOVER (1)** : Client recherche un serveur DHCP
- **OFFER (2)** : Serveur propose une configuration
- **REQUEST (3)** : Client demande une IP spécifique
- **DECLINE (4)** : Client refuse une IP
- **ACK (5)** : Serveur confirme l'attribution
- **NACK (6)** : Serveur refuse l'attribution
- **RELEASE (7)** : Client libère son IP
- **INFORM (8)** : Client demande des paramètres

## 🔧 Dépannage

### Erreurs communes

#### Erreur de permission
```
⛔ Erreur critique : [Errno 1] Operation not permitted
```
**Solution** : Exécuter avec `sudo` (Linux/macOS) ou en tant qu'administrateur (Windows)

#### Interface réseau non détectée
```
🔍 Interface détectée : None
```
**Solution** : Spécifier manuellement l'interface dans le code :
```python
iface = "eth0"  # ou votre interface réseau
```

#### Aucun paquet capturé
**Solutions possibles** :
- Vérifier que l'interface est active
- Contrôler la connectivité réseau
- Tester avec une autre interface réseau
- Vérifier les règles de pare-feu

### Debugging

Pour activer le mode debug, modifiez la ligne suivante dans le script :
```python
# Ajouter verbose=True pour plus de détails
sniff(filter="udp and (port 67 or port 68)", 
      prn=dhcp_monitor_enhanced, 
      store=0, 
      iface=iface,
      verbose=True)
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Voici comment contribuer :

1. **Fork** le projet
2. **Créer** une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. **Commiter** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrir** une Pull Request

### Guidelines de contribution

- Respecter le style de code existant
- Ajouter des tests pour les nouvelles fonctionnalités
- Mettre à jour la documentation si nécessaire
- S'assurer que tous les tests passent

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 👥 Auteurs

- **Iyotee** - *Développement initial* - [@iyotee](https://github.com/votre-username)

## 🙏 Remerciements

- Inspiré par les captures Wireshark et l'analyse de trafic réseau
- Merci à la communauté Scapy pour l'excellente bibliothèque
- Documentation DHCP RFC 2131 et RFC 2132

## 📞 Support

Si vous rencontrez des problèmes ou avez des questions :

- 🐛 **Issues** : [GitHub Issues](https://github.com/votre-username/dhcp-monitor-option50/issues)
- 💬 **Discussions** : [GitHub Discussions](https://github.com/votre-username/dhcp-monitor-option50/discussions)
- 📧 **Email** : votre.email@example.com

---

⭐ **N'oubliez pas de mettre une étoile au projet si il vous a été utile !**
