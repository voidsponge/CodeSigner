# 🔐 CodeSigner

Un outil robuste et sécurisé pour signer cryptographiquement votre code source. Protégez vos utilisateurs en leur permettant de vérifier l'authenticité et l'intégrité de votre code.

![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/security-RSA%204096-red.svg)
[![Quality Gate Status](http://87.106.163.166:9000/api/project_badges/measure?project=CiscoDerm_CodeSigner_AZVcvfSUwmLJAEZbk5_M&metric=alert_status&token=sqb_2acdaf67631b21a91d2e510b84970a70fe1c1008)](http://87.106.163.166:9000/dashboard?id=CiscoDerm_CodeSigner_AZVcvfSUwmLJAEZbk5_M)

## ✨ Caractéristiques

- 🔑 RSA 4096 bits pour une sécurité maximale
- 🛡️ Double hachage (SHA-256 + SHA3-512)
- 🔒 Chiffrement du manifeste des signatures
- ⏰ Vérification temporelle des signatures
- 🎯 Sélection flexible des fichiers par extension
- 🚨 Détection avancée des manipulations
- 📝 Rapports de vérification détaillés

## 🛡️ Fonctionnalités de Sécurité

- Protection contre les attaques Man-in-the-Middle
- Détection des replay attacks via timestamps
- Vérification multi-niveaux de l'intégrité
- Chiffrement de la clé privée par mot de passe
- Permissions système restrictives sur les fichiers sensibles
- Alertes sur les signatures périmées

## 📋 Prérequis

- Python 3.7 ou supérieur
- Package cryptography (`pip install cryptography`)

## 🛠️ Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/CiscoDerm/codesigner.git
cd codesigner
```

2. Installez les dépendances :
```bash
pip install cryptography
```

## 🖥️ Interface Graphique (GUI)

Pour utiliser la version graphique de l'outil (nécessite `tkinter`):

```bash
python codesigner_gui.py
```

L'interface vous permet de générer des clés, signer des fichiers et vérifier les signatures via des onglets intuitifs.

## 📖 Guide d'utilisation (Ligne de commande)

### Génération des clés (Développeur)

```bash
# Génération simple
python codesigner.py generate-keys

# Génération avec protection par mot de passe (recommandé)
python codesigner.py generate-keys --password "votre_mot_de_passe_fort"
```

Cela créera un dossier `keys` contenant :
- 🔒 `private_key.pem` (PRIVÉ - Ne jamais partager!)
- 🌐 `public_key.pem` (À distribuer aux utilisateurs)
- 🔑 `manifest.key` (Pour la vérification du manifeste)

### Signature de code (Développeur)

```bash
# Signature avec mot de passe
python codesigner.py sign --extensions .py --password "votre_mot_de_passe"

# Signature de plusieurs types de fichiers
python codesigner.py sign --directory ./mon_projet --extensions .py .js .css
```

### Distribution du code

Pour permettre à vos utilisateurs de vérifier votre code, fournissez :
1. 📦 Le code source
2. 📄 Le fichier `signatures.manifest`
3. 🔑 La clé publique (`public_key.pem`)
4. 🔐 La clé du manifeste (`manifest.key`)

### Vérification du code (Utilisateur)

```bash
# Vérification complète
python codesigner.py verify --public-key ./keys/public_key.pem --manifest-key ./keys/manifest.key
```

## 🎯 Exemple de sortie

```bash
mon_projet/main.py: ✓ Valide
mon_projet/utils.py: ✓ Valide
tests/test_main.py: ✓ Valide

Résumé de vérification:
- Fichiers vérifiés: 3/3
- Statut global: ✓ OK
```

## ⚠️ Bonnes pratiques de sécurité

1. 🔒 Protection de la clé privée :
   - Ne jamais partager votre clé privée
   - Utiliser un mot de passe fort
   - Sauvegarder la clé de manière sécurisée

2. 🔄 Gestion des signatures :
   - Signer à nouveau après chaque modification
   - Renouveler les signatures tous les 30 jours
   - Vérifier l'intégrité du manifeste régulièrement

3. 📢 Distribution :
   - Distribuer la clé publique via un canal sécurisé
   - Inclure des checksums pour les fichiers de vérification
   - Documenter la procédure de vérification

## 🔍 Diagnostics courants

- ⚠️ `Signature périmée` : La signature a plus de 30 jours
- ❌ `Hash invalide` : Le fichier a été modifié
- ⚠️ `Manifeste altéré` : Le fichier de signatures a été compromis
- ❌ `Fichier manquant` : Un fichier signé est absent

## 🤝 Contribution

Les contributions sont bienvenues ! Processus :

1. 🍴 Forker le projet
2. 🔨 Créer une branche (`git checkout -b feature/amelioration`)
3. 📝 Commiter vos changements
4. 🚀 Pusher vers la branche
5. 🎉 Ouvrir une Pull Request

## 📬 Contact

- Créé par [CiscoDerm]

---

⭐️ Si ce projet vous aide à sécuriser votre code, n'hésitez pas à lui donner une étoile sur GitHub !
