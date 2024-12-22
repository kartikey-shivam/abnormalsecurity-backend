from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode
from django.conf import settings
import os

class AESCipher:
    def __init__(self):
        # Use Django's SECRET_KEY as a base for key derivation
        salt = get_random_bytes(32)
        key = PBKDF2(settings.SECRET_KEY.encode(), salt, dkLen=32)
        self.key = key

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Pad data
        length = 16 - (len(data) % 16)
        data += bytes([length]) * length
        
        # Encrypt
        encrypted_data = cipher.encrypt(data)
        
        # Combine IV and encrypted data
        return b64encode(iv + encrypted_data).decode('utf-8')

    def decrypt(self, enc_data):
        enc_data = b64decode(enc_data)
        iv = enc_data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Decrypt
        decrypted_data = cipher.decrypt(enc_data[AES.block_size:])
        
        # Unpad
        padding_length = decrypted_data[-1]
        return decrypted_data[:-padding_length] 