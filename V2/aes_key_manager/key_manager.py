# aes_key_manager/key_manager.py
import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode

class AESKeyManager:
    def __init__(self, key_length=32):
        self.key_length = key_length  # AES-256 requires 32 bytes key

    def generate_key(self):
        key = os.urandom(self.key_length)
        return key

    def save_key(self, key, filename, password=None):
        key_data = {'key': urlsafe_b64encode(key).decode('utf-8')}
        if password:
            salt = os.urandom(16)
            key_data['salt'] = urlsafe_b64encode(salt).decode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            encryption_key = urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
            key_data['key'] = urlsafe_b64encode(kdf.encrypt(encryption_key, key_data['key'].encode('utf-8'))).decode('utf-8')

        with open(filename, 'w') as f:
            json.dump(key_data, f)

    def load_key(self, filename, password=None):
        with open(filename, 'r') as f:
            key_data = json.load(f)
        
        key = urlsafe_b64decode(key_data['key'].encode('utf-8'))
        if password:
            salt = urlsafe_b64decode(key_data['salt'].encode('utf-8'))
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            encryption_key = urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
            key = urlsafe_b64decode(kdf.decrypt(encryption_key, key))

        return key
