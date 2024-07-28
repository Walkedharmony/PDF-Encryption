import os
from tkinter import filedialog, Tk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_content(data, key):
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = iv + encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def insert_key_to_pdf(pdf_file, key_hex):
    with open(pdf_file, 'ab') as f:
        f.write(b'\n%%KEY_START\n')
        f.write(key_hex.encode('utf-8'))
        f.write(b'\n%%KEY_END\n')

def encrypt_pdf(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()

    encrypted_data = encrypt_content(data, key)

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

    key_hex = key.hex()
    insert_key_to_pdf(output_file, key_hex)

    print(f"File {input_file} encrypted successfully to {output_file}")

def get_key_manual():
    key_input = input("Enter the 32-byte key in hexadecimal (64 characters) or as bytes: ")
    
    try:
        key = bytes.fromhex(key_input)
    except ValueError:
        key = key_input.encode('utf-8')

    if len(key) != 32:
        raise ValueError("Invalid key length. Key must be 32 bytes.")
    
    return key

def generate_key_from_file():
    # Placeholder for actual AES key generation logic
    return os.urandom(32)

def choose_key_method():
    choice = input("Do you want to input the key manually? (yes/no): ").strip().lower()
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

    encrypt_pdf(input_file, output_file, key)

def main():
    encrypt_action()

if __name__ == "__main__":
    main()
