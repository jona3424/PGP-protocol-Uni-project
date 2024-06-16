import os
import glob
import base64
import zlib
import json
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageTk


# List to store key evidence
keys_list = []
def join_path(x, y):
    return os.path.join(x, y)
def open_file(filename, mode):
    with open(filename, mode) as file:
        return file
# Function to generate RSA key pair
def generate_keys(name, email, key_size, password):
    try:
        # Determine index for new key set
        index = 1
        while os.path.exists(f"{name}_{email}_key_set{index}"):
            index += 1

        key_dir = f"{name}_{email}_key_set{index}"
        os.makedirs(key_dir)

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

        f = open_file(join_path(key_dir, f"{name}_{email}_private_key.pem"), 'wb')
        f.write(private_key_pem)
        f = open_file(join_path(key_dir, f"{name}_{email}_public_key.pem"), 'wb')
        f.write(public_key_pem)

        keys_list.append((name, email, index,
                          join_path(key_dir, f"{name}_{email}_private_key.pem"),
                          join_path(key_dir, f"{name}_{email}_public_key.pem")))
        update_keys_listbox()
        update_comboboxes()

        messagebox.showinfo("Success", "Keys generated successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Key generation failed: {e}")

# Function to import keys
def import_keys():
    try:
        key_dir= filedialog.askdirectory(title="Select directory containing key files")
        if not key_dir:
            messagebox.showerror("Error", "Key directory not selected.")
            return
        files = os.listdir(key_dir)
        private_key_path = None
        public_key_path = None
        for file in files:
            if file.endswith("_private_key.pem"):
                private_key_path = join_path(key_dir, file)
            elif file.endswith("_public_key.pem"):
                public_key_path = join_path(key_dir, file)

        name = os.path.basename(private_key_path).split('_')[0]
        email = os.path.basename(private_key_path).split('_')[1]

        index =key_dir.split('_')[-1]


        keys_list.append((name, email, index, private_key_path, public_key_path))
        update_keys_listbox()
        update_comboboxes()

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

        key_dir= filedialog.askdirectory(title="Select directory where you want to save key files")
        if not key_dir:
            messagebox.showerror("Error", "Key directory not selected.")
            return

        key_type = messagebox.askquestion("Export Key", f"Export private key for {key_entry[0]} (set {key_entry[2]})?", icon='question')


        if key_dir:
            if key_type == 'yes':
                path = f"{key_entry[0]}_{key_entry[1]}_key_set{key_entry[2]}"
                new_private = join_path(key_dir, f"{path}_private_key.pem")
                new_public = join_path(key_dir, f"{path}_public_key.pem")
                private_key_path = key_entry[3]

                if private_key_path:
                    key_file = open_file(private_key_path, 'rb')
                    f = open_file(new_private, 'wb')
                    f.write(key_file.read())



            public_key_path = key_entry[4]
            if public_key_path:
                key_file = open_file(public_key_path, 'rb')
                f = open_file(new_public, 'wb')
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
        os.remove(key_entry[3])  # Remove private key file
        os.remove(key_entry[4])  # Remove public key file
        directories = glob.glob(join_path(f"{key_entry[0]}_{key_entry[1]}_key_set*"))
        for directory in directories:
            # Check if directory is empty
            if not os.listdir(directory):
                # If directory is empty, remove it
                os.rmdir(directory)

    update_keys_listbox()
    update_comboboxes()
    messagebox.showinfo("Success", "Key(s) deleted successfully!")

# Function to update keys listbox
def update_keys_listbox():
    keys_listbox.delete(0, tk.END)
    for key_entry in keys_list:
        keys_listbox.insert(tk.END, f"{key_entry[0]} ({key_entry[1]}) set {key_entry[2]}")

# Function to update comboboxes
def update_comboboxes():
    key_paths = get_key_paths()
    recipient_pub_key_dropdown['values'] = key_paths
    sender_pub_key_dropdown['values'] = key_paths
    recipient_priv_key_dropdown['values'] = key_paths
    if key_paths:
        recipient_pub_key_var.set(key_paths[0])
        sender_pub_key_var.set(key_paths[0])
        recipient_priv_key_var.set(key_paths[0])
    else:
        recipient_pub_key_var.set('')
        sender_pub_key_var.set('')
        recipient_priv_key_var.set('')

# Function to get key paths for dropdown menu
def get_key_paths():
    ret_list = []
    for key_entry in keys_list:
        ret_list.append(f"{key_entry[0]} ({key_entry[1]}) set {key_entry[2]}" )
    return ret_list

# Function to find key path based on selection
def find_key_path(selection):
    for key_entry in keys_list:
        if f"{key_entry[0]} ({key_entry[1]}) set {key_entry[2]}" == selection:
            return key_entry[3], key_entry[4]
    return None, None

# Function to encrypt and sign a message
def encrypt_and_sign_message(message, recipient_public_key_path, encryption_algo, sign, compress, radix64,
                             signing_key_path, password):
    if len(message) > 1024:
        messagebox.showerror("Error", f"Message length exceeds the limit of 1024 characters.")
        return

    metadata = {
        "compress": compress,
        "radix64": radix64,
        "encryption_algo": encryption_algo,
        "sign": sign
    }

    encrypted_message = message
    #there are 3 cases first when we jus want to sign then when we want just to encrypt and when we want to encrypt and sign
    #after all that we check if we want to convert the message to radix64
    #if we want to sign the message we just sign it and then check zip flag and zip if needed
    #if we want to encrypt the message we first zip the message if needed and then encrypt it also we need to encrypt the simetric enctyption_key with the public key of the reciever
    #if we want to encrypt and sign we first sign the message zip if needed and then we encrypt the message and the encryption_key and also we need to encrypt the simetric enctyption_key with the public key of the reciever
    #encrypt the message is done by aes or tripledes algorithms based on what is user choice
    #after all that we check if we want to convert the message to radix64 for every case
    #if we want to convert the message to radix64 we do that
    #after all that we save the message to the file
    #if we have a signature we save it to the file
    #if we have a encryption_key we save it to the file
    #we save metadata to the file

    signature = None
    if sign:
        try:
            f = open_file(signing_key_path, 'rb')
            signing_private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode(),
                backend=default_backend()
            )
            signature = signing_private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA1()
            )
            if compress:
                signature = zlib.compress(signature)
            if radix64:
                signature = base64.b64encode(signature).decode()
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {e}")
            return


    encryption_key = None
    if encryption_algo:
        encryption_key = os.urandom(24)
        if encryption_algo == "AES128":
            encryption_key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
        elif encryption_algo == "TripleDES":
            iv = os.urandom(8)
            cipher = Cipher(algorithms.TripleDES(encryption_key), modes.CFB(iv), backend=default_backend())
        else:
            messagebox.showerror("Error", "Unsupported encryption algorithm selected.")
            return

        encryptor = cipher.encryptor()

        if compress:
            message = zlib.compress(message.encode())
            encrypted_message = encryptor.update(message) + encryptor.finalize()
        else:
            encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()

        encrypted_message = iv + encrypted_message

        if radix64:
            encrypted_message = base64.b64encode(encrypted_message).decode()

    if not encryption_algo:
        if compress:
            encrypted_message = zlib.compress(message.encode())
        if radix64:
            encrypted_message = base64.b64encode(encrypted_message).decode()


    #encode this encryprion key wirh the public key of the reciever
    if encryption_key:
        f = open_file(recipient_public_key_path, 'rb')
        recipient_public_key_pem = f.read()
        recipient_public_key = serialization.load_pem_public_key(
            recipient_public_key_pem,
            backend=default_backend()
        )
        encryption_key = recipient_public_key.encrypt(
            encryption_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

    save_path = filedialog.askdirectory(title="Select Destination Directory")
    if not save_path:
        messagebox.showerror("Error", "Destination directory not selected.")
        return

    encrypted_message_path = join_path(save_path, "encrypted_message.txt")
    metadata_path = join_path(save_path, "metadata.json")
    signature_path = join_path(save_path, "signature.txt")
    encryption_key_path = join_path(save_path, "encryption_key.txt")

    try:
        if radix64:
            f = open_file(encrypted_message_path, 'w')
            f.write(encrypted_message)
            if signature:
                f = open_file(signature_path, 'w')
                f.write(signature)
        elif not radix64 and not signature and not encryption_algo:
            f = open_file(encrypted_message_path, 'w')
            f.write(encrypted_message)
        else:
            f = open_file(encrypted_message_path, 'wb')
            f.write(encrypted_message)

            if signature:
                f = open_file(signature_path, 'wb')
                f.write(signature)


        f = open_file(metadata_path, 'w')
        json.dump(metadata, f)

        if encryption_key:
            f = open_file(encryption_key_path, 'wb')
            f.write(encryption_key)

        messagebox.showinfo("Success", "Message encrypted and signed successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"File saving failed: {e}")

# Function to decrypt and verify a message
def decrypt_and_verify_message(encrypted_message_path, metadata_path, signature_path, sender_public_key_path,
                               recipient_private_key_path, password,simetric_key_path):

    try:
        f = open_file(metadata_path, 'r')
        metadata = json.load(f)

        signature = None
        decrypted_message = None

        if metadata["radix64"]:
            f = open_file(encrypted_message_path, 'r')
            encrypted_message = f.read()
            encrypted_message = base64.b64decode(encrypted_message)
            if metadata["sign"]:
                f = open_file(signature_path, 'r')
                signature = f.read()
                signature=base64.b64decode(signature)
            if metadata["encryption_algo"]:
                f = open_file(simetric_key_path,'r')
                simetric_key = f.read()
                simetric_key=base64.b64decode(simetric_key)
        else:
            f = open_file(encrypted_message_path, 'rb')
            encrypted_message = f.read()
            if metadata["sign"]:
                f = open_file(signature_path, 'rb')
                signature = f.read()
            if metadata["encryption_algo"]:
                f = open_file(simetric_key_path,'rb')
                simetric_key = f.read()

        print(encrypted_message)
        if metadata["sign"]:
            if metadata["compress"]:
                signature=zlib.decompress(signature)

            f = open_file(sender_public_key_path, 'rb')
            sender_public_key_pem = f.read()
            sender_public_key = serialization.load_pem_public_key(
                sender_public_key_pem,
                backend=default_backend()
            )

        f = open_file(recipient_private_key_path, 'rb')
        recipient_private_key_pem = f.read()

        recipient_private_key = serialization.load_pem_private_key(
            recipient_private_key_pem,
            password=password.encode(),
            backend=default_backend()
        )


        if metadata["encryption_algo"]:

            if metadata["encryption_algo"] == "AES128":
                iv = encrypted_message[:16]
                encrypted_message = encrypted_message[16:]
            else:
                iv = encrypted_message[:8]
                encrypted_message = encrypted_message[8:]

            # now we need to decode symetric key with recievers rivate key
            simetric_key = recipient_private_key.decrypt(
                simetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

            if metadata["encryption_algo"] == "AES128":
                cipher = Cipher(
                    algorithms.AES(simetric_key),
                    modes.CFB(iv),
                    backend=default_backend()
                )
            elif metadata["encryption_algo"] == "TripleDES":
                cipher = Cipher(
                    algorithms.TripleDES(simetric_key),
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
            if metadata["compress"]:
                decrypted_message = zlib.decompress(encrypted_message)

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

       # decrypted_message = decrypted_message.decode()

        save_path = filedialog.asksaveasfilename(title="Save Decrypted Message As", defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt")])
        if not save_path:
            messagebox.showerror("Error", "Destination file not selected.")
            return

        f = open_file(save_path, 'wb')
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
        f = open_file(metadata_path, 'r')
        metadata = json.load(f)

        decrypt_button.config(state=tk.NORMAL)

        entries['enc_msg'].delete(0, tk.END)
        entries['enc_msg'].insert(0, metadata_path.replace("metadata.json", "encrypted_message.txt"))
        entries['metadata'].delete(0, tk.END)
        entries['metadata'].insert(0, metadata_path)
        entries['signature'].delete(0, tk.END)
        entries['signature'].insert(0, metadata_path.replace("metadata.json", "signature.txt"))
        entries['simetric_key'] = metadata_path.replace("metadata.json", "encryption_key.txt")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to load metadata: {e}")

# GUI Setup
def setup_gui():
    root = tk.Tk()
    root.title("PGP Email Security")
    root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}")

    # Load the background image
    bg_image = Image.open("hello_kitty.png")
    bg_image = bg_image.resize((root.winfo_screenwidth(), root.winfo_screenheight()), Image.LANCZOS)
    bg_photo = ImageTk.PhotoImage(bg_image)

    # Create a canvas to display the background image
    canvas = tk.Canvas(root, width=root.winfo_screenwidth(), height=root.winfo_screenheight())
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, anchor="nw", image=bg_photo)

    # Configure styles
    style = ttk.Style()
    style.configure("TFrame", background="#f5e1f7")  # Match the background to the image background color
    style.configure("TEntry", background="#f5e1f7", fieldbackground="#f5e1f7")
    style.configure("TLabel", background="#f5e1f7")

    def create_frame(parent, x, y, width):
        frame = ttk.Frame(parent, style="TFrame")
        canvas.create_window(x, y, window=frame, anchor="nw", width=width)
        return frame

    def create_entry(parent, row, column, width=20):
        entry = ttk.Entry(parent, style="TEntry", width=width)
        entry.grid(row=row, column=column, padx=5, pady=5, ipadx=5, ipady=5, sticky="we")
        return entry

    def create_label(parent, text, row, column):
        label = ttk.Label(parent, text=text, style="TLabel")
        label.grid(row=row, column=column, padx=5, pady=5, sticky="w")
        return label

    global recipient_pub_key_var, sender_pub_key_var, recipient_priv_key_var
    global recipient_pub_key_dropdown, sender_pub_key_dropdown, recipient_priv_key_dropdown

    # Key Generation Frame
    frame_gen = create_frame(canvas, 10, 10, 300)

    create_label(frame_gen, "Name:", 0, 0)
    create_label(frame_gen, "Email:", 1, 0)
    create_label(frame_gen, "Key Size:", 2, 0)
    create_label(frame_gen, "Password:", 3, 0)

    entry_name = create_entry(frame_gen, 0, 1)
    entry_email = create_entry(frame_gen, 1, 1)

    # Radio buttons for key size
    key_size_var = tk.IntVar(value=1024)
    ttk.Radiobutton(frame_gen, text="1024", variable=key_size_var, value=1024).grid(row=2, column=1, padx=5, pady=5,
                                                                                    sticky='w')
    ttk.Radiobutton(frame_gen, text="2048", variable=key_size_var, value=2048).grid(row=2, column=1, padx=5, pady=5,
                                                                                    sticky='e')

    entry_password = ttk.Entry(frame_gen, show='*', style="TEntry")
    entry_password.grid(row=3, column=1, padx=5, pady=5, sticky="we")

    def generate_keys_callback():
        generate_keys(entry_name.get(), entry_email.get(), key_size_var.get(), entry_password.get())

    ttk.Button(frame_gen, text="Generate Keys", command=generate_keys_callback).grid(row=4, columnspan=2, pady=10)

    # Key Management Frame
    frame_manage = create_frame(canvas, 10, 195, 300)

    ttk.Button(frame_manage, text="Import Keys", command=import_keys).grid(row=0, column=0, padx=5, pady=5)
    ttk.Button(frame_manage, text="Export Keys", command=export_keys).grid(row=0, column=1, padx=5, pady=5)
    ttk.Button(frame_manage, text="Delete Keys", command=delete_keys).grid(row=0, column=2, padx=5, pady=5)

    # Listbox to display keys
    global keys_listbox
    keys_listbox = tk.Listbox(frame_manage, selectmode=tk.MULTIPLE)
    keys_listbox.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky='we')

    # Message Encryption Frame
    frame_encrypt = create_frame(canvas, 10, 404, 300)

    create_label(frame_encrypt, "Message:", 0, 0)
    create_label(frame_encrypt, "Recipient Public Key:", 1, 0)
    create_label(frame_encrypt, "Encryption Algorithm:", 2, 0)
    create_label(frame_encrypt, "Password:", 3, 0)
    create_label(frame_encrypt, "Sign Message:", 4, 0)
    create_label(frame_encrypt, "Compress Message:", 5, 0)
    create_label(frame_encrypt, "Convert to Radix-64:", 6, 0)

    entry_message = create_entry(frame_encrypt, 0, 1)

    # Dropdown for recipient public key
    recipient_pub_key_paths = get_key_paths()
    if recipient_pub_key_paths:
        recipient_pub_key_var = tk.StringVar(value=recipient_pub_key_paths[0])
    else:
        recipient_pub_key_var = tk.StringVar(value="")
    recipient_pub_key_dropdown = ttk.Combobox(frame_encrypt, textvariable=recipient_pub_key_var,
                                              values=recipient_pub_key_paths)
    recipient_pub_key_dropdown.grid(row=1, column=1, padx=5, pady=5)

    # Dropdown for encryption algorithm
    encryption_algo_var = tk.StringVar(value="AES128")
    encryption_algo_dropdown = ttk.Combobox(frame_encrypt, textvariable=encryption_algo_var,
                                            values=["AES128", "TripleDES", ""])
    encryption_algo_dropdown.grid(row=2, column=1, padx=5, pady=5)

    entry_enc_password = create_entry(frame_encrypt, 3, 1)
    entry_enc_password.config(show='*')

    sign_var = tk.IntVar()
    ttk.Checkbutton(frame_encrypt, variable=sign_var).grid(row=4, column=1, padx=5, pady=5)
    compress_var = tk.IntVar()
    ttk.Checkbutton(frame_encrypt, variable=compress_var).grid(row=5, column=1, padx=5, pady=5)
    radix64_var = tk.IntVar()
    ttk.Checkbutton(frame_encrypt, variable=radix64_var).grid(row=6, column=1, padx=5, pady=5)

    def encrypt_message_callback():
        signing_key_path = None
        if sign_var.get() == 1:
            signing_key_path = filedialog.askopenfilename(title="Select Signing Private Key")
            if not signing_key_path:
                messagebox.showerror("Error", "Signing private key not selected.")
                return
        recipient_priv_key, recipient_pub_key = find_key_path(recipient_pub_key_var.get())
        encrypt_and_sign_message(entry_message.get(), recipient_pub_key, encryption_algo_var.get(),
                                 sign_var.get() == 1, compress_var.get() == 1, radix64_var.get() == 1,
                                 signing_key_path, entry_enc_password.get() if sign_var.get() == 1 else None)

    ttk.Button(frame_encrypt, text="Encrypt and Sign Message", command=encrypt_message_callback).grid(row=7,
                                                                                                      columnspan=2,
                                                                                                      pady=10)

    # Message Decryption Frame
    frame_decrypt = create_frame(canvas, 10, 677, 300)

    create_label(frame_decrypt, "Encrypted Message:", 0, 0)
    create_label(frame_decrypt, "Metadata:", 1, 0)
    create_label(frame_decrypt, "Signature:", 2, 0)
    create_label(frame_decrypt, "Sender Public Key:", 3, 0)
    create_label(frame_decrypt, "Recipient Private Key:", 4, 0)
    create_label(frame_decrypt, "Password:", 5, 0)

    entry_enc_msg = create_entry(frame_decrypt, 0, 1)
    entry_metadata = create_entry(frame_decrypt, 1, 1)
    entry_signature = create_entry(frame_decrypt, 2, 1)

    # Dropdown for sender public key
    sender_pub_key_paths = get_key_paths()
    if sender_pub_key_paths:
        sender_pub_key_var = tk.StringVar(value=sender_pub_key_paths[0])
    else:
        sender_pub_key_var = tk.StringVar(value="")
    sender_pub_key_dropdown = ttk.Combobox(frame_decrypt, textvariable=sender_pub_key_var, values=sender_pub_key_paths)
    sender_pub_key_dropdown.grid(row=3, column=1, padx=5, pady=5)

    # Dropdown for recipient private key
    recipient_priv_key_paths = get_key_paths()
    if recipient_priv_key_paths:
        recipient_priv_key_var = tk.StringVar(value=recipient_priv_key_paths[0])
    else:
        recipient_priv_key_var = tk.StringVar(value="")

    recipient_priv_key_dropdown = ttk.Combobox(frame_decrypt, textvariable=recipient_priv_key_var,
                                               values=recipient_priv_key_paths)
    recipient_priv_key_dropdown.grid(row=4, column=1, padx=5, pady=5)

    entry_dec_password = create_entry(frame_decrypt, 5, 1)
    entry_dec_password.config(show='*')

    entries = {
        'enc_msg': entry_enc_msg,
        'metadata': entry_metadata,
        'signature': entry_signature,
        'simetric_key': None
    }

    decrypt_button = ttk.Button(frame_decrypt, text="Decrypt and Verify Message",
                                command=lambda: decrypt_and_verify_message(
                                    entry_enc_msg.get(),
                                    entry_metadata.get(),
                                    entry_signature.get(),
                                    find_key_path(sender_pub_key_var.get())[1] if entries['signature'].get() else None,
                                    find_key_path(recipient_priv_key_var.get())[0],
                                    entry_dec_password.get(),
                                    entries['simetric_key']

                                ))
    decrypt_button.grid(row=6, columnspan=2, pady=10)
    decrypt_button.config(state=tk.DISABLED)

    ttk.Button(frame_decrypt, text="Load Metadata", command=lambda: load_metadata(entries, decrypt_button)).grid(row=7,
                                                                                                                 columnspan=2,
                                                                                                                 pady=10)

    root.mainloop()


# Run the GUI setup
setup_gui()