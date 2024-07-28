import os
import sys
import tempfile
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QLabel, QVBoxLayout, QWidget
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import fitz  

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
    temp_dir = tempfile.gettempdir()
    pdf_filename = os.path.basename(pdf_file)
    key_filename = f"{pdf_filename}-key"
    key_file_path = os.path.join(temp_dir, key_filename)

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
        
       
        with open(key_file_path, 'w') as key_f:
            key_f.write(key_hex)
        
        
        new_content = content[:start_index-len(start_marker)] + content[end_index+len(end_marker):]
        
        
        with open(pdf_file, 'wb') as f:
            f.write(new_content)
        
        return key_file_path

def get_key_for_pdf(pdf_file):
    temp_dir = tempfile.gettempdir()
    pdf_filename = os.path.basename(pdf_file)
    key_filename = f"{pdf_filename}-key"
    key_file_path = os.path.join(temp_dir, key_filename)
    
    if not os.path.exists(key_file_path):
        raise ValueError("Key file not found in the temp directory.")
    
    with open(key_file_path, 'r') as key_f:
        key_hex = key_f.read()
    
    return bytes.fromhex(key_hex)

def decrypt_pdf(input_file):
    temp_dir = tempfile.gettempdir()
    pdf_filename = os.path.basename(input_file)
    key_filename = f"{pdf_filename}-key"
    key_file_path = os.path.join(temp_dir, key_filename)
    
    
    if not os.path.exists(key_file_path):
        extract_key_from_pdf(input_file)
    
    key = get_key_for_pdf(input_file)
    
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    
    decrypted_data = decrypt_content(encrypted_data, key)
    
   
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
        temp_file.write(decrypted_data)
        temp_file_path = temp_file.name
    
    return temp_file_path

class PDFViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('AES Encrypted PDF Viewer')
        self.setGeometry(100, 100, 800, 600)
        
        self.label = QLabel('No PDF loaded', self)
        self.label.setAlignment(Qt.AlignCenter)
        
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)
        
        self.show()

    def open_pdf(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Encrypted PDF", "", "PDF Files (*.pdf);;All Files (*)", options=options)
        if file_path:
            try:
                decrypted_file = decrypt_pdf(file_path)
                self.display_pdf(decrypted_file)
                os.remove(decrypted_file)  
            except Exception as e:
                self.label.setText(f"Error: {e}")

    def display_pdf(self, file_path):
        doc = fitz.open(file_path)
        page = doc.load_page(0)  
        pix = page.get_pixmap()
        
        img = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGB888)
        self.label.setPixmap(QPixmap.fromImage(img).scaled(self.label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    viewer = PDFViewer()
    viewer.open_pdf()
    sys.exit(app.exec_())
