import json
import os
from tkinter import filedialog, Tk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from aes_key_manager.key_manager import AESKeyManager  

def encrypt_file(input_file, output_file, key):
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = iv + encryptor.update(padded_data) + encryptor.finalize()
    
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
    
    print(f"File {input_file} berhasil dienkripsi ke {output_file}")

def get_key_manual():
    key_input = input("Masukkan kunci 32-byte dalam heksadesimal (64 karakter) atau sebagai byte: ")
    
    try:
     
        key = bytes.fromhex(key_input)
    except ValueError:
   
        key = key_input.encode('utf-8')

    if len(key) != 32:
        raise ValueError("Panjang kunci tidak valid. Kunci harus sepanjang 32 byte.")
    
    key_hex = key.hex()
    print(f"Kunci yang dimasukkan adalah: {key_hex}")
    return key

def generate_key_from_file():
    manager = AESKeyManager()
    key = manager.generate_key()
    return key

def save_key_to_json(input_filename, encrypted_filename, key):
    key_data = {
        "input_filename": input_filename,
        "encrypted_filename": encrypted_filename,
        "key": key.hex()
    }
    file_path = "key.json"
    
    if os.path.exists(file_path):
        with open(file_path, 'r+') as file:
            data = json.load(file)
            data.append(key_data)
            file.seek(0)
            json.dump(data, file, indent=4)
    else:
        with open(file_path, 'w') as file:
            json.dump([key_data], file, indent=4)

def choose_key_method():
    choice = input("Apakah Anda ingin memasukkan kunci secara manual? (yes/no): ").strip().lower()
    if choice == 'yes':
        return get_key_manual()
    else:
        return generate_key_from_file()

def encrypt_action():
    root = Tk()
    root.withdraw()  

    input_file = filedialog.askopenfilename(title="Select the PDF file to encrypt", filetypes=[("PDF files", "*.pdf")])
    if not input_file:
        print("No file selected.")
        return

    output_file = filedialog.asksaveasfilename(title="Save encrypted PDF as", defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if not output_file:
        print("No output file selected.")
        return

    key = choose_key_method()
    if not key:
        return

    save_key_to_json(os.path.basename(input_file), os.path.basename(output_file), key)
    encrypt_file(input_file, output_file, key)

def main():
    encrypt_action()

if __name__ == "__main__":
    main()
