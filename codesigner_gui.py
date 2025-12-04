import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import sys
import os
import threading
from codesigner import CodeSigner, SignatureManifest

class CodeSignerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CodeSigner GUI")
        self.root.geometry("800x600")

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Main container
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)

        # Tabs
        self.tab_gen = ttk.Frame(self.notebook)
        self.tab_sign = ttk.Frame(self.notebook)
        self.tab_verify = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_gen, text='Générer Clés')
        self.notebook.add(self.tab_sign, text='Signer Code')
        self.notebook.add(self.tab_verify, text='Vérifier Signatures')

        self.setup_gen_tab()
        self.setup_sign_tab()
        self.setup_verify_tab()

        # Console output
        self.create_console()

    def create_console(self):
        frame = ttk.LabelFrame(self.root, text="Logs / Sortie")
        frame.pack(fill='both', expand=True, padx=10, pady=5)

        self.console = scrolledtext.ScrolledText(frame, height=10, state='disabled')
        self.console.pack(fill='both', expand=True)

    def log(self, message):
        self.console.configure(state='normal')
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)
        self.console.configure(state='disabled')
        self.root.update_idletasks()

    def setup_gen_tab(self):
        frame = ttk.Frame(self.tab_gen, padding="20")
        frame.pack(fill='both', expand=True)

        # Password
        ttk.Label(frame, text="Mot de passe (optionnel):").grid(row=0, column=0, sticky='w', pady=5)
        self.gen_pwd = ttk.Entry(frame, show="*")
        self.gen_pwd.grid(row=0, column=1, sticky='ew', pady=5)

        # Output directory
        ttk.Label(frame, text="Dossier de destination:").grid(row=1, column=0, sticky='w', pady=5)
        self.gen_dir = ttk.Entry(frame)
        self.gen_dir.insert(0, "./keys")
        self.gen_dir.grid(row=1, column=1, sticky='ew', pady=5)
        ttk.Button(frame, text="Parcourir", command=lambda: self.browse_dir(self.gen_dir)).grid(row=1, column=2, padx=5)

        # Button
        ttk.Button(frame, text="Générer les Clés", command=self.generate_keys).grid(row=2, column=1, pady=20)

        frame.columnconfigure(1, weight=1)

    def setup_sign_tab(self):
        frame = ttk.Frame(self.tab_sign, padding="20")
        frame.pack(fill='both', expand=True)

        # Directory to sign
        ttk.Label(frame, text="Dossier à signer:").grid(row=0, column=0, sticky='w', pady=5)
        self.sign_dir = ttk.Entry(frame)
        self.sign_dir.insert(0, ".")
        self.sign_dir.grid(row=0, column=1, sticky='ew', pady=5)
        ttk.Button(frame, text="Parcourir", command=lambda: self.browse_dir(self.sign_dir)).grid(row=0, column=2, padx=5)

        # Private Key
        ttk.Label(frame, text="Clé Privée:").grid(row=1, column=0, sticky='w', pady=5)
        self.sign_key = ttk.Entry(frame)
        self.sign_key.insert(0, "./keys/private_key.pem")
        self.sign_key.grid(row=1, column=1, sticky='ew', pady=5)
        ttk.Button(frame, text="Parcourir", command=lambda: self.browse_file(self.sign_key)).grid(row=1, column=2, padx=5)

        # Manifest Key
        ttk.Label(frame, text="Clé Manifeste:").grid(row=2, column=0, sticky='w', pady=5)
        self.sign_m_key = ttk.Entry(frame)
        self.sign_m_key.insert(0, "./keys/manifest.key")
        self.sign_m_key.grid(row=2, column=1, sticky='ew', pady=5)
        ttk.Button(frame, text="Parcourir", command=lambda: self.browse_file(self.sign_m_key)).grid(row=2, column=2, padx=5)

        # Password
        ttk.Label(frame, text="Mot de passe clé privée:").grid(row=3, column=0, sticky='w', pady=5)
        self.sign_pwd = ttk.Entry(frame, show="*")
        self.sign_pwd.grid(row=3, column=1, sticky='ew', pady=5)

        # Extensions
        ttk.Label(frame, text="Extensions (ex: .py .js):").grid(row=4, column=0, sticky='w', pady=5)
        self.sign_ext = ttk.Entry(frame)
        self.sign_ext.insert(0, ".py .js")
        self.sign_ext.grid(row=4, column=1, sticky='ew', pady=5)

        # Button
        ttk.Button(frame, text="Signer", command=self.sign_code).grid(row=5, column=1, pady=20)

        frame.columnconfigure(1, weight=1)

    def setup_verify_tab(self):
        frame = ttk.Frame(self.tab_verify, padding="20")
        frame.pack(fill='both', expand=True)

        # Directory to verify
        ttk.Label(frame, text="Dossier à vérifier:").grid(row=0, column=0, sticky='w', pady=5)
        self.ver_dir = ttk.Entry(frame)
        self.ver_dir.insert(0, ".")
        self.ver_dir.grid(row=0, column=1, sticky='ew', pady=5)
        ttk.Button(frame, text="Parcourir", command=lambda: self.browse_dir(self.ver_dir)).grid(row=0, column=2, padx=5)

        # Public Key
        ttk.Label(frame, text="Clé Publique:").grid(row=1, column=0, sticky='w', pady=5)
        self.ver_key = ttk.Entry(frame)
        self.ver_key.insert(0, "./keys/public_key.pem")
        self.ver_key.grid(row=1, column=1, sticky='ew', pady=5)
        ttk.Button(frame, text="Parcourir", command=lambda: self.browse_file(self.ver_key)).grid(row=1, column=2, padx=5)

        # Manifest Key
        ttk.Label(frame, text="Clé Manifeste (Optionnel):").grid(row=2, column=0, sticky='w', pady=5)
        self.ver_m_key = ttk.Entry(frame)
        self.ver_m_key.insert(0, "./keys/manifest.key")
        self.ver_m_key.grid(row=2, column=1, sticky='ew', pady=5)
        ttk.Button(frame, text="Parcourir", command=lambda: self.browse_file(self.ver_m_key)).grid(row=2, column=2, padx=5)

        # Button
        ttk.Button(frame, text="Vérifier", command=self.verify_code).grid(row=3, column=1, pady=20)

        frame.columnconfigure(1, weight=1)

    def browse_dir(self, entry):
        dirname = filedialog.askdirectory()
        if dirname:
            entry.delete(0, tk.END)
            entry.insert(0, dirname)

    def browse_file(self, entry):
        filename = filedialog.askopenfilename()
        if filename:
            entry.delete(0, tk.END)
            entry.insert(0, filename)

    def run_async(self, func):
        threading.Thread(target=func, daemon=True).start()

    def generate_keys(self):
        pwd = self.gen_pwd.get()
        directory = self.gen_dir.get()

        if not directory:
            messagebox.showerror("Erreur", "Veuillez sélectionner un dossier de destination")
            return

        def task():
            try:
                self.log(f"Génération des clés dans {directory}...")
                signer = CodeSigner()
                signer.generate_keypair(directory, pwd if pwd else None)
                self.log("Clés générées avec succès !")
                messagebox.showinfo("Succès", "Clés générées avec succès !")
            except Exception as e:
                self.log(f"Erreur: {str(e)}")
                messagebox.showerror("Erreur", str(e))

        self.run_async(task)

    def sign_code(self):
        directory = self.sign_dir.get()
        key_path = self.sign_key.get()
        manifest_key_path = self.sign_m_key.get()
        pwd = self.sign_pwd.get()
        extensions = self.sign_ext.get().split()

        if not directory or not key_path or not manifest_key_path:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs obligatoires")
            return

        def task():
            try:
                self.log(f"Début de la signature dans {directory}...")
                signer = CodeSigner()

                # Load Manifest Key
                signer.load_manifest_key(manifest_key_path)

                # Load Private Key
                if pwd:
                    signer.load_private_key(key_path, pwd)
                else:
                    signer.load_private_key(key_path)

                # Load existing manifest if it exists
                if os.path.exists(signer.manifest_file):
                    try:
                        signer.manifest = SignatureManifest.load(signer.manifest_file, signer.encryption_key)
                        self.log("Manifeste existant chargé.")
                    except Exception as e:
                        self.log(f"Attention: Impossible de charger le manifeste existant: {e}. Création d'un nouveau.")

                count = 0
                for root, _, files in os.walk(directory):
                    for file in files:
                        if not extensions or any(file.endswith(ext) for ext in extensions):
                            file_path = os.path.join(root, file)
                            self.log(f"Signature de {file_path}")
                            signer.sign_file(file_path)
                            count += 1

                signer.manifest.save(signer.manifest_file, signer.encryption_key)
                self.log(f"Signature terminée. {count} fichiers signés.")
                messagebox.showinfo("Succès", f"Signature terminée.\n{count} fichiers signés.")

            except Exception as e:
                self.log(f"Erreur: {str(e)}")
                messagebox.showerror("Erreur", str(e))

        self.run_async(task)

    def verify_code(self):
        directory = self.ver_dir.get()
        key_path = self.ver_key.get()
        manifest_key_path = self.ver_m_key.get()

        if not directory or not key_path:
            messagebox.showerror("Erreur", "Veuillez remplir les champs obligatoires")
            return

        def task():
            try:
                self.log(f"Vérification dans {directory}...")
                signer = CodeSigner()
                signer.load_public_key(key_path)

                if manifest_key_path and os.path.exists(manifest_key_path):
                    signer.load_manifest_key(manifest_key_path)

                if not os.path.exists(signer.manifest_file):
                    self.log("Erreur: Fichier signatures.manifest introuvable.")
                    return

                try:
                    signer.manifest = SignatureManifest.load(
                        signer.manifest_file,
                        signer.encryption_key
                    )
                except Exception as e:
                    self.log(f"Erreur chargement manifeste: {e}")
                    return

                all_valid = True
                total_files = len(signer.manifest.signatures)
                verified_files = 0

                for file_path in signer.manifest.signatures.keys():
                    if os.path.exists(file_path):
                        is_valid = signer.verify_file(file_path)
                        status = '✓ Valide' if is_valid else '✗ INVALIDE'
                        self.log(f"{file_path}: {status}")
                        all_valid = all_valid and is_valid
                        if is_valid:
                            verified_files += 1
                    else:
                        self.log(f"⚠️ Fichier manquant: {file_path}")
                        all_valid = False

                result_msg = f"Vérification terminée.\nValidés: {verified_files}/{total_files}"
                self.log(result_msg)
                self.log(f"Statut global: {'✓ OK' if all_valid else '✗ ÉCHEC'}")

                if all_valid:
                    messagebox.showinfo("Succès", "Vérification réussie !\nTous les fichiers sont valides.")
                else:
                    messagebox.showwarning("Attention", "Certains fichiers sont invalides ou manquants.")

            except Exception as e:
                self.log(f"Erreur: {str(e)}")
                messagebox.showerror("Erreur", str(e))

        self.run_async(task)

if __name__ == "__main__":
    root = tk.Tk()
    app = CodeSignerGUI(root)
    root.mainloop()
