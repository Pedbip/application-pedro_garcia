from cryptography.fernet import Fernet

def encrypt_data(key, data: str):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(key, encrypted_data):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()