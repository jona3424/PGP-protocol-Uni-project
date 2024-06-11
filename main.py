import os
import base64
import zlib
import json
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants for limits
MAX_MESSAGE_LENGTH = 1024  # Example limit for message length

# List to store key evidence
keys_list = []

# Function to generate RSA key pair
def generate_keys(name, email, key_size, password):
    try:
        private_key = crypto_rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_key_path = f"{name}_{email}_private_key.pem"
        public_key_path = f"{name}_{email}_public_key.pem"

        with open(private_key_path, 'wb') as f:
            f.write(private_key_pem)
        with open(public_key_path, 'wb') as f:
            f.write(public_key_pem)

        keys_list.append((name, email, private_key_path, public_key_path))
        update_keys_listbox()

        messagebox.showinfo("Success", "Keys generated successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Key generation failed: {e}")

# Function to import keys
def import_keys():
    try:
        private_key_path = filedialog.askopenfilename(title="Select Private Key File")
        public_key_path = filedialog.askopenfilename(title="Select Public Key File")

        name = os.path.basename(private_key_path).split('_')[0]
        email = os.path.basename(private_key_path).split('_')[1]

        with open(private_key_path, 'rb') as f:
            private_key_pem = f.read()
        with open(public_key_path, 'rb') as f:
            public_key_pem = f.read()

        with open(os.path.basename(private_key_path), 'wb') as f:
            f.write(private_key_pem)
        with open(os.path.basename(public_key_path), 'wb') as f:
            f.write(public_key_pem)

        keys_list.append((name, email, private_key_path, public_key_path))
        update_keys_listbox()

        messagebox.showinfo("Success", "Keys imported successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Key import failed: {e}")

# Function to export keys
def export_keys():
    selected_keys = keys_listbox.curselection()
    if not selected_keys:
        messagebox.showerror("Error", "No keys selected for export.")
        return

    for index in selected_keys:
        key_entry = keys_list[index]
        key_type = messagebox.askquestion("Export Key", f"Export private key for {key_entry[0]}?", icon='question')
        key_path = filedialog.asksaveasfilename(title="Save Key File", defaultextension=".pem",
                                                filetypes=[("PEM files", "*.pem")])

        if key_path:
            if key_type == 'yes':
                private_key_path = key_entry[2]
                if private_key_path:
                    with open(private_key_path, 'rb') as key_file:
                        with open(key_path, 'wb') as f:
                            f.write(key_file.read())
            else:
                public_key_path = key_entry[3]
                if public_key_path:
                    with open(public_key_path, 'rb') as key_file:
                        with open(key_path, 'wb') as f:
                            f.write(key_file.read())

    messagebox.showinfo("Success", "Key(s) exported successfully!")

# Function to delete keys
def delete_keys():
    selected_keys = keys_listbox.curselection()
    if not selected_keys:
        messagebox.showerror("Error", "No keys selected for deletion.")
        return

    for index in reversed(selected_keys):
        key_entry = keys_list.pop(index)
        os.remove(key_entry[2])  # Remove private key file
        os.remove(key_entry[3])  # Remove public key file

    update_keys_listbox()
    messagebox.showinfo("Success", "Key(s) deleted successfully!")

# Function to update keys listbox
def update_keys_listbox():
    keys_listbox.delete(0, tk.END)
    for key_entry in keys_list:
        keys_listbox.insert(tk.END, f"{key_entry[0]} ({key_entry[1]})")

# Function to encrypt and sign a message
def encrypt_and_sign_message(message, recipient_public_key_path, encryption_algo, sign, compress, radix64,
                             signing_key_path, password):
    if len(message) > MAX_MESSAGE_LENGTH:
        messagebox.showerror("Error", f"Message length exceeds the limit of {MAX_MESSAGE_LENGTH} characters.")
        return

    metadata = {
        "compress": compress,
        "radix64": radix64,
        "encryption_algo": encryption_algo,
        "sign": sign
    }

    encrypted_message = message
    encryption_key = None
    if encryption_algo:
        encryption_key = os.urandom(32) if encryption_algo == "AES128" else os.urandom(24)  # Key length
        if encryption_algo == "AES128":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
        elif encryption_algo == "TripleDES":
            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(encryption_key), modes.CFB(iv), backend=default_backend())
        else:
            messagebox.showerror("Error", "Unsupported encryption algorithm selected.")
            return

        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_message = iv + encrypted_message

        if compress:
            encrypted_message = zlib.compress(encrypted_message)

    if radix64:
        encrypted_message = base64.b64encode(encrypted_message).decode()

    signature = None
    if sign:
        try:
            with open(signing_key_path, 'rb') as f:
                signing_private_key_pem = f.read()
            signing_private_key = serialization.load_pem_private_key(
                signing_private_key_pem,
                password=password.encode(),
                backend=default_backend()
            )
            signature = signing_private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA1()
            )
            signature = base64.b64encode(signature).decode()
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {e}")
            return

    save_path = filedialog.askdirectory(title="Select Destination Directory")
    if not save_path:
        messagebox.showerror("Error", "Destination directory not selected.")
        return

    encrypted_message_path = os.path.join(save_path, "encrypted_message.txt")
    metadata_path = os.path.join(save_path, "metadata.json")
    signature_path = os.path.join(save_path, "signature.txt")
    encryption_key_path = os.path.join(save_path, "encryption_key.txt")

    try:
        if radix64:
            with open(encrypted_message_path, 'w') as f:
                f.write(encrypted_message)
        else:
            with open(encrypted_message_path, 'wb') as f:
                f.write(encrypted_message)

        with open(metadata_path, 'w') as f:
            json.dump(metadata, f)
        if signature:
            with open(signature_path, 'w') as f:
                f.write(signature)
        if encryption_key:
            with open(encryption_key_path, 'wb') as f:
                f.write(encryption_key)
        messagebox.showinfo("Success", "Message encrypted and signed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"File saving failed: {e}")

# Function to decrypt and verify a message
def decrypt_and_verify_message(encrypted_message_path, metadata_path, signature_path, sender_public_key_path,
                               recipient_private_key_path, password):
    try:
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        if metadata["radix64"]:
            with open(encrypted_message_path, 'r') as f:
                encrypted_message = f.read()
            encrypted_message = base64.b64decode(encrypted_message)
        else:
            with open(encrypted_message_path, 'rb') as f:
                encrypted_message = f.read()

        signature = None
        if metadata["sign"]:
            with open(signature_path, 'r') as f:
                signature = base64.b64decode(f.read())

            with open(sender_public_key_path, 'rb') as f:
                sender_public_key_pem = f.read()
            sender_public_key = serialization.load_pem_public_key(
                sender_public_key_pem,
                backend=default_backend()
            )

        with open(recipient_private_key_path, 'rb') as f:
            recipient_private_key_pem = f.read()

        recipient_private_key = serialization.load_pem_private_key(
            recipient_private_key_pem,
            password=password.encode(),
            backend=default_backend()
        )

        decrypted_message = None
        if metadata["encryption_algo"]:
            iv = encrypted_message[:16] if metadata["encryption_algo"] == "AES128" else encrypted_message[:8]
            encrypted_message = encrypted_message[16:] if metadata["encryption_algo"] == "AES128" else encrypted_message[8:]

            with open(os.path.join(os.path.dirname(encrypted_message_path), "encryption_key.txt"), 'rb') as f:
                encryption_key = f.read()

            if metadata["encryption_algo"] == "AES128":
                cipher = Cipher(
                    algorithms.AES(encryption_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
            elif metadata["encryption_algo"] == "TripleDES":
                cipher = Cipher(
                    algorithms.TripleDES(encryption_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
            else:
                messagebox.showerror("Error", "Unsupported encryption algorithm selected.")
                return

            decryptor = cipher.decryptor()
            decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

            if metadata["compress"]:
                decrypted_message = zlib.decompress(decrypted_message)
        else:
            decrypted_message = encrypted_message  # Treat it as plain text

        if metadata["sign"]:
            try:
                sender_public_key.verify(
                    signature,
                    decrypted_message,
                    padding.PKCS1v15(),
                    hashes.SHA1()
                )
            except Exception as e:
                messagebox.showerror("Error", f"Signature verification failed: {e}")
                return

        decrypted_message = decrypted_message.decode()

        save_path = filedialog.asksaveasfilename(title="Save Decrypted Message As", defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt")])
        if not save_path:
            messagebox.showerror("Error", "Destination file not selected.")
            return

        with open(save_path, 'w') as f:
            f.write(decrypted_message)

        messagebox.showinfo("Success", "Message decrypted and signature verified successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# Function to enable/disable fields based on metadata
def load_metadata(entries, decrypt_button):
    metadata_path = filedialog.askopenfilename(title="Select Metadata File", filetypes=[("JSON files", "*.json")])
    if not metadata_path:
        messagebox.showerror("Error", "Metadata file not selected.")
        return

    try:
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        decrypt_button.config(state=tk.NORMAL)

        entries['enc_msg'].delete(0, tk.END)
        entries['enc_msg'].insert(0, metadata_path.replace("metadata.json", "encrypted_message.txt"))
        entries['metadata'].delete(0, tk.END)
        entries['metadata'].insert(0, metadata_path)
        entries['signature'].delete(0, tk.END)
        entries['signature'].insert(0, metadata_path.replace("metadata.json", "signature.txt"))

    except Exception as e:
        messagebox.showerror("Error", f"Failed to load metadata: {e}")

# GUI Setup
def setup_gui():
    root = tk.Tk()
    root.title("PGP Email Security")

    # Key Generation Frame
    frame_gen = tk.Frame(root)
    frame_gen.pack(padx=10, pady=10)

    tk.Label(frame_gen, text="Name:").grid(row=0, column=0, padx=5, pady=5)
    tk.Label(frame_gen, text="Email:").grid(row=1, column=0, padx=5, pady=5)
    tk.Label(frame_gen, text="Key Size:").grid(row=2, column=0, padx=5, pady=5)
    tk.Label(frame_gen, text="Password:").grid(row=3, column=0, padx=5, pady=5)

    entry_name = tk.Entry(frame_gen)
    entry_name.grid(row=0, column=1, padx=5, pady=5)
    entry_email = tk.Entry(frame_gen)
    entry_email.grid(row=1, column=1, padx=5, pady=5)

    # Radio buttons for key size
    key_size_var = tk.IntVar(value=1024)
    tk.Radiobutton(frame_gen, text="1024", variable=key_size_var, value=1024).grid(row=2, column=1, padx=5, pady=5, sticky='w')
    tk.Radiobutton(frame_gen, text="2048", variable=key_size_var, value=2048).grid(row=2, column=1, padx=5, pady=5, sticky='e')

    entry_password = tk.Entry(frame_gen, show='*')
    entry_password.grid(row=3, column=1, padx=5, pady=5)

    def generate_keys_callback():
        generate_keys(entry_name.get(), entry_email.get(), key_size_var.get(), entry_password.get())

    tk.Button(frame_gen, text="Generate Keys", command=generate_keys_callback).grid(row=4, columnspan=2, pady=10)

    # Key Management Frame
    frame_manage = tk.Frame(root)
    frame_manage.pack(padx=10, pady=10)

    tk.Button(frame_manage, text="Import Keys", command=import_keys).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(frame_manage, text="Export Keys", command=export_keys).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(frame_manage, text="Delete Keys", command=delete_keys).grid(row=0, column=2, padx=5, pady=5)

    # Listbox to display keys
    global keys_listbox
    keys_listbox = tk.Listbox(frame_manage, selectmode=tk.MULTIPLE)
    keys_listbox.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky='we')

    # Message Encryption Frame
    frame_encrypt = tk.Frame(root)
    frame_encrypt.pack(padx=10, pady=10)

    tk.Label(frame_encrypt, text="Message:").grid(row=0, column=0, padx=5, pady=5)
    tk.Label(frame_encrypt, text="Recipient Public Key:").grid(row=1, column=0, padx=5, pady=5)
    tk.Label(frame_encrypt, text="Encryption Algorithm:").grid(row=2, column=0, padx=5, pady=5)
    tk.Label(frame_encrypt, text="Password:").grid(row=3, column=0, padx=5, pady=5)
    tk.Label(frame_encrypt, text="Sign Message:").grid(row=4, column=0, padx=5, pady=5)
    tk.Label(frame_encrypt, text="Compress Message:").grid(row=5, column=0, padx=5, pady=5)
    tk.Label(frame_encrypt, text="Convert to Radix-64:").grid(row=6, column=0, padx=5, pady=5)

    entry_message = tk.Entry(frame_encrypt)
    entry_message.grid(row=0, column=1, padx=5, pady=5)
    entry_recipient_pub_key = tk.Entry(frame_encrypt)
    entry_recipient_pub_key.grid(row=1, column=1, padx=5, pady=5)

    # Dropdown for encryption algorithm
    encryption_algo_var = tk.StringVar()
    encryption_algo_dropdown = tk.OptionMenu(frame_encrypt, encryption_algo_var, "AES128", "TripleDES", "")
    encryption_algo_dropdown.grid(row=2, column=1, padx=5, pady=5)

    entry_enc_password = tk.Entry(frame_encrypt, show='*')
    entry_enc_password.grid(row=3, column=1, padx=5, pady=5)

    sign_var = tk.IntVar()
    tk.Checkbutton(frame_encrypt, variable=sign_var).grid(row=4, column=1, padx=5, pady=5)
    compress_var = tk.IntVar()
    tk.Checkbutton(frame_encrypt, variable=compress_var).grid(row=5, column=1, padx=5, pady=5)
    radix64_var = tk.IntVar()
    tk.Checkbutton(frame_encrypt, variable=radix64_var).grid(row=6, column=1, padx=5, pady=5)

    def encrypt_message_callback():
        signing_key_path = None
        if sign_var.get() == 1:
            signing_key_path = filedialog.askopenfilename(title="Select Signing Private Key")
            if not signing_key_path:
                messagebox.showerror("Error", "Signing private key not selected.")
                return
        encrypt_and_sign_message(entry_message.get(), entry_recipient_pub_key.get(), encryption_algo_var.get(),
                                 sign_var.get() == 1, compress_var.get() == 1, radix64_var.get() == 1,
                                 signing_key_path, entry_enc_password.get() if sign_var.get() == 1 else None)

    tk.Button(frame_encrypt, text="Encrypt and Sign Message", command=encrypt_message_callback).grid(row=7, columnspan=2, pady=10)

    # Message Decryption Frame
    frame_decrypt = tk.Frame(root)
    frame_decrypt.pack(padx=10, pady=10)

    tk.Label(frame_decrypt, text="Encrypted Message:").grid(row=0, column=0, padx=5, pady=5)
    tk.Label(frame_decrypt, text="Metadata:").grid(row=1, column=0, padx=5, pady=5)
    tk.Label(frame_decrypt, text="Signature:").grid(row=2, column=0, padx=5, pady=5)
    tk.Label(frame_decrypt, text="Sender Public Key:").grid(row=3, column=0, padx=5, pady=5)
    tk.Label(frame_decrypt, text="Recipient Private Key:").grid(row=4, column=0, padx=5, pady=5)
    tk.Label(frame_decrypt, text="Password:").grid(row=5, column=0, padx=5, pady=5)

    entry_enc_msg = tk.Entry(frame_decrypt)
    entry_enc_msg.grid(row=0, column=1, padx=5, pady=5)
    entry_metadata = tk.Entry(frame_decrypt)
    entry_metadata.grid(row=1, column=1, padx=5, pady=5)
    entry_signature = tk.Entry(frame_decrypt)
    entry_signature.grid(row=2, column=1, padx=5, pady=5)
    entry_sender_pub_key = tk.Entry(frame_decrypt)
    entry_sender_pub_key.grid(row=3, column=1, padx=5, pady=5)
    entry_recipient_priv_key = tk.Entry(frame_decrypt)
    entry_recipient_priv_key.grid(row=4, column=1, padx=5, pady=5)
    entry_dec_password = tk.Entry(frame_decrypt, show='*')
    entry_dec_password.grid(row=5, column=1, padx=5, pady=5)

    entries = {
        'enc_msg': entry_enc_msg,
        'metadata': entry_metadata,
        'signature': entry_signature
    }

    decrypt_button = tk.Button(frame_decrypt, text="Decrypt and Verify Message",
                               command=lambda: decrypt_and_verify_message(
                                   entry_enc_msg.get(),
                                   entry_metadata.get(),
                                   entry_signature.get(),
                                   entry_sender_pub_key.get() if entries['signature'].get() else None,
                                   entry_recipient_priv_key.get(),
                                   entry_dec_password.get()
                               ))
    decrypt_button.grid(row=6, columnspan=2, pady=10)
    decrypt_button.config(state=tk.DISABLED)

    tk.Button(frame_decrypt, text="Load Metadata", command=lambda: load_metadata(entries, decrypt_button)).grid(row=7, columnspan=2, pady=10)

    root.mainloop()

# Run the GUI setup
setup_gui()
