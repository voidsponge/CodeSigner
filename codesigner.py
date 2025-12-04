from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import json
import os
import argparse
from pathlib import Path
import sys
import hashlib
import time
import secrets

class SignatureManifest:
    def __init__(self):
        self.signatures = {}
        self.metadata = {
            "timestamp": "",
            "manifest_hash": "",
            "version": "1.0"
        }

    def add_signature(self, file_path: str, signature: str, file_hash: str):
        relative_path = os.path.relpath(file_path)
        self.signatures[relative_path] = {
            "signature": signature,
            "file_hash": file_hash,
            "timestamp": int(time.time())
        }

    def save(self, filename: str, encryption_key: bytes = None):
        data = {
            "signatures": self.signatures,
            "metadata": self.metadata
        }

        # Calcul du hash du manifeste
        manifest_content = json.dumps(data["signatures"], sort_keys=True).encode()
        data["metadata"]["manifest_hash"] = hashlib.sha256(manifest_content).hexdigest()
        data["metadata"]["timestamp"] = int(time.time())

        if encryption_key:
            # Chiffrement du manifeste
            f = Fernet(encryption_key)
            encrypted_data = f.encrypt(json.dumps(data).encode())
            with open(filename, 'wb') as f:
                f.write(encrypted_data)
        else:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)

    @staticmethod
    def load(filename: str, encryption_key: bytes = None):
        manifest = SignatureManifest()

        if not os.path.exists(filename):
            return manifest

        try:
            if encryption_key:
                with open(filename, 'rb') as f:
                    encrypted_data = f.read()
                f = Fernet(encryption_key)
                data = json.loads(f.decrypt(encrypted_data))
            else:
                with open(filename, 'r') as f:
                    data = json.load(f)

            # Vérification de l'intégrité du manifeste
            stored_hash = data["metadata"]["manifest_hash"]
            manifest_content = json.dumps(data["signatures"], sort_keys=True).encode()
            calculated_hash = hashlib.sha256(manifest_content).hexdigest()

            if stored_hash != calculated_hash:
                raise ValueError("Le manifeste a été altéré")

            manifest.signatures = data["signatures"]
            manifest.metadata = data["metadata"]

        except Exception as e:
            raise ValueError(f"Erreur lors du chargement du manifeste: {str(e)}")

        return manifest

class CodeSigner:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.manifest = SignatureManifest()
        self.manifest_file = "signatures.manifest"
        self.encryption_key = None

    def generate_keypair(self, save_path="./keys", password: str = None):
        """Génère une nouvelle paire de clés RSA et les sauvegarde de manière sécurisée"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # Augmentation de la taille de la clé
            backend=default_backend()
        )
        self.private_key = private_key
        self.public_key = private_key.public_key()

        # Génération d'une clé de chiffrement pour le manifeste
        self.encryption_key = base64.urlsafe_b64encode(secrets.token_bytes(32))

        # Création du dossier keys s'il n'existe pas
        os.makedirs(save_path, exist_ok=True)

        # Dérivation de la clé pour le chiffrement de la clé privée
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption_algorithm = serialization.NoEncryption()

        # Sauvegarde des clés
        private_path = os.path.join(save_path, "private_key.pem")
        public_path = os.path.join(save_path, "public_key.pem")
        manifest_key_path = os.path.join(save_path, "manifest.key")

        with open(private_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))

        with open(public_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        with open(manifest_key_path, 'wb') as f:
            f.write(self.encryption_key)

        # Définition des permissions restrictives
        os.chmod(private_path, 0o600)  # Lecture/écriture uniquement par le propriétaire
        os.chmod(manifest_key_path, 0o600)

        print(f"Clés générées et sauvegardées dans {save_path}")
        return private_path, public_path

    def calculate_file_hash(self, file_path: str) -> tuple:
        """Calcule les hashes SHA-256 et SHA-3-512 d'un fichier"""
        sha256 = hashlib.sha256()
        sha3_512 = hashlib.sha3_512()

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
                sha3_512.update(chunk)

        return sha256.digest(), sha3_512.hexdigest()

    def sign_file(self, file_path: str) -> str:
        """Signe un fichier et met à jour le manifeste"""
        if not self.private_key:
            raise ValueError("Aucune clé privée n'a été chargée")

        # Calcul des hashes du fichier
        file_hash, file_hash_sha3 = self.calculate_file_hash(file_path)

        # Signature avec double hachage et padding PSS
        signature = self.private_key.sign(
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Encodage de la signature
        signature_b64 = base64.b64encode(signature).decode('utf-8')

        # Mise à jour du manifeste
        self.manifest.add_signature(file_path, signature_b64, file_hash_sha3)

        return signature_b64

    def verify_file(self, file_path: str) -> bool:
        """Vérifie la signature d'un fichier"""
        if not self.public_key:
            raise ValueError("Aucune clé publique n'a été chargée")

        relative_path = os.path.relpath(file_path)
        if relative_path not in self.manifest.signatures:
            print(f"Aucune signature trouvée pour {relative_path}")
            return False

        sig_info = self.manifest.signatures[relative_path]

        try:
            # Calcul unique des hashs pour optimisation
            file_hash, current_hash_sha3 = self.calculate_file_hash(file_path)

            # Vérification du hash SHA-3
            if current_hash_sha3 != sig_info["file_hash"]:
                print(f"Le hash du fichier {relative_path} ne correspond pas")
                return False

            # Vérification de la signature
            signature = base64.b64decode(sig_info["signature"])

            self.public_key.verify(
                signature,
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Vérification de l'âge de la signature (optionnel)
            age = int(time.time()) - sig_info["timestamp"]
            if age > 30 * 24 * 3600:  # 30 jours
                print(f"⚠️ Attention: La signature de {relative_path} a plus de 30 jours")

            return True

        except Exception as e:
            print(f"Erreur de vérification pour {relative_path}: {str(e)}")
            return False

    def load_private_key(self, key_path: str, password: str = None):
        """Charge une clé privée depuis un fichier"""
        with open(key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()

    def load_public_key(self, key_path: str):
        """Charge une clé publique depuis un fichier"""
        with open(key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def load_manifest_key(self, key_path: str):
        """Charge la clé de chiffrement du manifeste"""
        with open(key_path, 'rb') as f:
            self.encryption_key = f.read()

def verify_directory(directory: str, public_key_path: str, manifest_key_path: str = None):
    """Vérifie tous les fichiers signés d'un répertoire"""
    signer = CodeSigner()

    try:
        signer.load_public_key(public_key_path)
        if manifest_key_path:
            signer.load_manifest_key(manifest_key_path)

        signer.manifest = SignatureManifest.load(
            signer.manifest_file,
            signer.encryption_key
        )

        if not signer.manifest.signatures:
            print("Aucune signature trouvée dans le manifeste")
            return False

        all_valid = True
        total_files = len(signer.manifest.signatures)
        verified_files = 0

        for file_path in signer.manifest.signatures.keys():
            if os.path.exists(file_path):
                is_valid = signer.verify_file(file_path)
                status = '✓ Valide' if is_valid else '✗ Invalid'
                print(f"{file_path}: {status}")
                all_valid = all_valid and is_valid
                if is_valid:
                    verified_files += 1
            else:
                print(f"⚠️ Fichier manquant: {file_path}")
                all_valid = False

        print(f"\nRésumé de vérification:")
        print(f"- Fichiers vérifiés: {verified_files}/{total_files}")
        print(f"- Statut global: {'✓ OK' if all_valid else '✗ ÉCHEC'}")

        # Vérification de l'âge du manifeste
        manifest_age = int(time.time()) - int(signer.manifest.metadata["timestamp"])
        if manifest_age > 30 * 24 * 3600:  # 30 jours
            print("⚠️ Attention: Le manifeste a plus de 30 jours")

        return all_valid

    except Exception as e:
        print(f"Erreur lors de la vérification: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Outil de signature de code sécurisé')
    parser.add_argument('action', choices=['sign', 'verify', 'generate-keys'],
                       help='Action à effectuer')
    parser.add_argument('--directory', '-d', default='.',
                       help='Répertoire à traiter')
    parser.add_argument('--extensions', '-e', nargs='+',
                       help='Extensions de fichiers à signer (ex: .py .js)')
    parser.add_argument('--public-key', '-p',
                       help='Chemin vers la clé publique pour la vérification')
    parser.add_argument('--manifest-key', '-m',
                       help='Chemin vers la clé de chiffrement du manifeste')
    parser.add_argument('--private-key',
                       help='Chemin vers la clé privée pour la signature')
    parser.add_argument('--password',
                       help='Mot de passe pour la clé privée')

    args = parser.parse_args()

    try:
        if args.action == 'generate-keys':
            signer = CodeSigner()
            signer.generate_keypair(password=args.password)

        elif args.action == 'sign':
            signer = CodeSigner()
            private_key_path = args.private_key if args.private_key else "keys/private_key.pem"
            manifest_key_path = args.manifest_key if args.manifest_key else "keys/manifest.key"

            if args.password:
                signer.load_private_key(private_key_path, args.password)
            else:
                signer.load_private_key(private_key_path)

            signer.load_manifest_key(manifest_key_path)

            # Charger le manifeste existant s'il existe
            if os.path.exists(signer.manifest_file):
                try:
                    signer.manifest = SignatureManifest.load(signer.manifest_file, signer.encryption_key)
                except Exception as e:
                    print(f"Attention: Impossible de charger le manifeste existant: {e}. Création d'un nouveau.")

            for root, _, files in os.walk(args.directory):
                for file in files:
                    if args.extensions is None or any(file.endswith(ext) for ext in args.extensions):
                        file_path = os.path.join(root, file)
                        print(f"Signature de {file_path}")
                        signer.sign_file(file_path)

            signer.manifest.save(signer.manifest_file, signer.encryption_key)

        elif args.action == 'verify':
            public_key_path = args.public_key if args.public_key else "keys/public_key.pem"
            manifest_key_path = args.manifest_key if args.manifest_key else "keys/manifest.key"

            if not os.path.exists(public_key_path):
                 print(f"Erreur: Clé publique non trouvée: {public_key_path}")
                 sys.exit(1)

            success = verify_directory(args.directory, public_key_path, manifest_key_path)
            sys.exit(0 if success else 1)

    except Exception as e:
        print(f"Erreur: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()