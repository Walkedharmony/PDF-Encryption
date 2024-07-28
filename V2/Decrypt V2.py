import os
from tkinter import filedialog, Tk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def decrypt_content(data, key):
    iv = data[:16]
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_plaintext = decryptor.update(data[16:]) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

def extract_key_from_pdf(pdf_file):
    with open(pdf_file, 'rb') as f:
        content = f.read()
        start_marker = b'\n%%KEY_START\n'
        end_marker = b'\n%%KEY_END\n'
        start_index = content.find(start_marker)
        end_index = content.find(end_marker, start_index + len(start_marker))
        
        if start_index == -1 or end_index == -1:
            raise ValueError("Key not found in the PDF file.")
        
        start_index += len(start_marker)
        key_hex = content[start_index:end_index].decode('utf-8')
        return bytes.fromhex(key_hex)

def decrypt_pdf(input_file, output_file):
    key = extract_key_from_pdf(input_file)
    
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    
    # Remove the key section from the encrypted data
    start_marker = b'\n%%KEY_START\n'
    end_marker = b'\n%%KEY_END\n'
    start_index = encrypted_data.find(start_marker)
    encrypted_data = encrypted_data[:start_index]
    
    decrypted_data = decrypt_content(encrypted_data, key)

    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"File {input_file} decrypted successfully to {output_file}")

def decrypt_action():
    root = Tk()
    root.withdraw()

    input_file = filedialog.askopenfilename(title="Select the encrypted PDF file", filetypes=[("PDF files", "*.pdf")])
    if not input_file:
        print("No file selected.")
        return

    output_file = filedialog.asksaveasfilename(title="Save decrypted PDF as", defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if not output_file:
        print("No output file selected.")
        return

    decrypt_pdf(input_file, output_file)

def main():
    decrypt_action()

if __name__ == "__main__":
    main()
