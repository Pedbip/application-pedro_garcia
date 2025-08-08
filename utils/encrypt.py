from cryptography.fernet import Fernet

def encrypt_data(key, data: str) -> str:
    f = Fernet(key)
    encrypted_bytes = f.encrypt(data.encode())
    return encrypted_bytes.decode('utf-8')  # Converte bytes para string

def decrypt_data(key, encrypted_data: str) -> str:
    f = Fernet(key)
    encrypted_bytes = encrypted_data.encode('utf-8')  # Converte string para bytes
    return f.decrypt(encrypted_bytes).decode()