import os
import json
import logging
from PyQt5.QtWidgets import QApplication, QFileDialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Setup logger
log_format = "%(levelname)s %(message)s"
logging.basicConfig(format=log_format, level=logging.DEBUG)
logger = logging.getLogger()

def decrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f:
            ciphertext = f.read()

        iv = ciphertext[:16]
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        logger.info(f"Berkas {input_file} berhasil didekripsi ke {output_file}")
    except Exception as e:
        logger.error(f"Terjadi kesalahan selama dekripsi: {e}")

def select_file(prompt, filter):
    app = QApplication([])
    dialog = QFileDialog()
    dialog.setWindowTitle(prompt)
    dialog.setFileMode(QFileDialog.ExistingFile)
    dialog.setNameFilter(filter)
    if dialog.exec_():
        file_path = dialog.selectedFiles()[0]
        return file_path
    return None

def get_save_file(prompt, filter):
    app = QApplication([])
    dialog = QFileDialog()
    dialog.setWindowTitle(prompt)
    dialog.setAcceptMode(QFileDialog.AcceptSave)
    dialog.setNameFilter(filter)
    if dialog.exec_():
        file_path = dialog.selectedFiles()[0]
        return file_path
    return None

def get_key_manual():
    key_input = input("Masukkan kunci 32-byte dalam heksadesimal (64 karakter) atau sebagai byte: ")
    try:
        key = bytes.fromhex(key_input)
    except ValueError:
        key = key_input.encode('utf-8')

    if len(key) != 32:
        raise ValueError("Panjang kunci tidak valid. Kunci harus 32 byte.")

    return key

def get_key_from_json(encrypted_filename):
    json_file = select_file("Pilih berkas key.json", "JSON files (*.json)")
    if not json_file:
        logger.info("Berkas key.json tidak ditemukan.")
        return None

    with open(json_file, 'r') as file:
        data = json.load(file)
        for item in data:
            if item['encrypted_filename'] == os.path.basename(encrypted_filename):
                key_hex = item['key']
                key = bytes.fromhex(key_hex)
                logger.info(f"Kunci yang ditemukan untuk {encrypted_filename} adalah: {key_hex}")
                return key

    logger.error("Kunci untuk berkas terenkripsi tidak ditemukan dalam key.json.")
    return None

def main():
    input_file = select_file("Pilih berkas terenkripsi", "PDF files (*.pdf)")
    if not input_file:
        logger.info("Berkas tidak ditemukan.")
        return

    output_file = get_save_file("Simpan PDF terdekripsi sebagai", "PDF files (*.pdf)")
    if not output_file:
        logger.info("Tidak ada berkas keluaran yang dipilih.")
        return

    choice = input("Apakah Anda ingin memasukkan kunci secara manual? (yes/no): ").strip().lower()
    if choice == "yes":
        key = get_key_manual()
    else:
        key = get_key_from_json(input_file)

    if not key:
        return

    decrypt_file(input_file, output_file, key)

if __name__ == "__main__":
    main()
