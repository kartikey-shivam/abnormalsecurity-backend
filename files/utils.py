from cryptography.fernet import Fernet
from django.conf import settings
import os

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_data, key):
    f = Fernet(key)
    return f.encrypt(file_data)

def decrypt_file(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data)

def handle_uploaded_file(uploaded_file, user):
    from .models import EncryptedFile
    
    # Generate encryption key
    key = generate_key()
    
    # Read and encrypt file content
    file_content = uploaded_file.read()
    encrypted_content = encrypt_file(file_content, key)
    
    # Create a new filename
    filename = "encrypted_{}".format(uploaded_file.name)
    
    # Save encrypted file
    encrypted_file = EncryptedFile(
        uploaded_by=user,
        original_filename=uploaded_file.name,
        encryption_key=key
    )
    
    # Save the encrypted content to a temporary file
    temp_path = os.path.join(settings.MEDIA_ROOT, filename)
    with open(temp_path, 'wb') as f:
        f.write(encrypted_content)
        
    # Attach the file to the model and save
    with open(temp_path, 'rb') as f:
        encrypted_file.file.save(filename, f)
    
    # Clean up temporary file
    os.remove(temp_path)
    
    return encrypted_file 