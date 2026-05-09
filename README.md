# 🛡️ Automated Network Security Audit Tool

Ce projet est un script Python d'automatisation d'audit réseau exploitant **Nmap**. Il a été conçu dans une optique défensive (Blue Team / SOC) pour cartographier rapidement les actifs d'un réseau, identifier les services exposés et générer des rapports structurés.

## ⚙️ Fonctionnalités
* **Scan Automatisé :** Découverte des hôtes actifs et scan des ports (TCP SYN).
* **Détection de Services :** Identification des services en cours d'exécution et de leurs versions (`-sV`).
* **Reporting Structuré :** Génération automatique de rapports au format JSON, prêts à être ingérés par un SIEM ou un outil d'analyse de logs.

## 🛠️ Technologies Utilisées
* **Python 3**
* **Bibliothèque `python-nmap`**
* **Nmap** (Backend)

## 🚀 Installation & Utilisation

1. Assurez-vous que Nmap est installé sur votre système.
2. Clonez le dépôt et installez les dépendances :
```bash
git clone [https://github.com/alaeboukria/Auto-Network-Audit.git](https://github.com/alaeboukria/Auto-Network-Audit.git)
cd Auto-Network-Audit
pip install -r requirements.txt