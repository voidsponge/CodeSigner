import unittest
import os
import shutil
import sys
import json
import base64
import time
from pathlib import Path

# Add parent directory to path to import codesigner
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codesigner import CodeSigner, SignatureManifest

class TestCodeSigner(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_env"
        self.keys_dir = os.path.join(self.test_dir, "keys")
        self.src_dir = os.path.join(self.test_dir, "src")

        # Clean up
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        if os.path.exists("signatures.manifest"):
            os.remove("signatures.manifest")

        os.makedirs(self.keys_dir)
        os.makedirs(self.src_dir)

        # Create dummy files
        with open(os.path.join(self.src_dir, "test1.py"), "w") as f:
            f.write("print('hello')")
        with open(os.path.join(self.src_dir, "test2.js"), "w") as f:
            f.write("console.log('hello')")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        if os.path.exists("signatures.manifest"):
            os.remove("signatures.manifest")

    def test_generate_keys(self):
        signer = CodeSigner()
        signer.generate_keypair(self.keys_dir, password="password123")

        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "private_key.pem")))
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "public_key.pem")))
        self.assertTrue(os.path.exists(os.path.join(self.keys_dir, "manifest.key")))

    def test_sign_and_verify(self):
        # Generate keys
        signer = CodeSigner()
        signer.generate_keypair(self.keys_dir, password="password123")

        # Sign
        signer.load_private_key(os.path.join(self.keys_dir, "private_key.pem"), "password123")
        signer.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))

        file_path = os.path.join(self.src_dir, "test1.py")
        signer.sign_file(file_path)
        signer.manifest.save("signatures.manifest", signer.encryption_key)

        # Verify
        verifier = CodeSigner()
        verifier.load_public_key(os.path.join(self.keys_dir, "public_key.pem"))
        verifier.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))
        verifier.manifest = SignatureManifest.load("signatures.manifest", verifier.encryption_key)

        self.assertTrue(verifier.verify_file(file_path))

    def test_manifest_update(self):
        """Test that signing a new file updates the manifest instead of overwriting it."""
        # Generate keys
        signer = CodeSigner()
        signer.generate_keypair(self.keys_dir, password="password123")

        # Sign first file
        signer.load_private_key(os.path.join(self.keys_dir, "private_key.pem"), "password123")
        signer.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))

        file1 = os.path.join(self.src_dir, "test1.py")
        signer.sign_file(file1)
        signer.manifest.save("signatures.manifest", signer.encryption_key)

        # Simulate a new run - load manifest first (this logic is in main(), but here we test the class usage pattern)
        # If we use the class directly, we must manually load the manifest.
        # But let's verify that if we DO load it, it works.

        signer2 = CodeSigner()
        signer2.load_private_key(os.path.join(self.keys_dir, "private_key.pem"), "password123")
        signer2.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))
        signer2.manifest = SignatureManifest.load("signatures.manifest", signer2.encryption_key)

        file2 = os.path.join(self.src_dir, "test2.js")
        signer2.sign_file(file2)
        signer2.manifest.save("signatures.manifest", signer2.encryption_key)

        # Check manifest
        manifest = SignatureManifest.load("signatures.manifest", signer2.encryption_key)
        self.assertIn(os.path.relpath(file1), manifest.signatures)
        self.assertIn(os.path.relpath(file2), manifest.signatures)

    def test_tampering_detection(self):
        # Generate keys
        signer = CodeSigner()
        signer.generate_keypair(self.keys_dir, password="password123")

        # Sign
        signer.load_private_key(os.path.join(self.keys_dir, "private_key.pem"), "password123")
        signer.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))

        file_path = os.path.join(self.src_dir, "test1.py")
        signer.sign_file(file_path)
        signer.manifest.save("signatures.manifest", signer.encryption_key)

        # Tamper with file
        with open(file_path, "a") as f:
            f.write("\n# malicious code")

        # Verify
        verifier = CodeSigner()
        verifier.load_public_key(os.path.join(self.keys_dir, "public_key.pem"))
        verifier.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))
        verifier.manifest = SignatureManifest.load("signatures.manifest", verifier.encryption_key)

        # It should fail verification
        self.assertFalse(verifier.verify_file(file_path))

    def test_manifest_tampering(self):
         # Generate keys
        signer = CodeSigner()
        signer.generate_keypair(self.keys_dir, password="password123")

        # Sign
        signer.load_private_key(os.path.join(self.keys_dir, "private_key.pem"), "password123")
        signer.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))

        file_path = os.path.join(self.src_dir, "test1.py")
        signer.sign_file(file_path)
        signer.manifest.save("signatures.manifest", signer.encryption_key)

        # Tamper with manifest (it's encrypted, so just corrupting bytes)
        with open("signatures.manifest", "rb") as f:
            data = f.read()

        with open("signatures.manifest", "wb") as f:
            f.write(data[:-1] + b'0') # Change last byte

        verifier = CodeSigner()
        verifier.load_public_key(os.path.join(self.keys_dir, "public_key.pem"))
        verifier.load_manifest_key(os.path.join(self.keys_dir, "manifest.key"))

        # Loading should fail due to decryption error or integrity check
        with self.assertRaises(Exception):
             verifier.manifest = SignatureManifest.load("signatures.manifest", verifier.encryption_key)

if __name__ == '__main__':
    unittest.main()
