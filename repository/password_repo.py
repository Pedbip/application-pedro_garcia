from models import password as pwd
from fastapi import HTTPException, status
from sqlmodel import select
from utils.database import SessionDep
from datetime import datetime
from utils import encrypt
import os, secrets, string

def generate_password_string(size: int, use_numbers: bool, use_special_char: bool) -> str:
    characters = string.ascii_letters
    if use_numbers:
        characters += string.digits
    if use_special_char:
        characters += string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(size))

def generate_secure_password(request: pwd.PasswordGen, db: SessionDep):
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption key not configured")
    password_str = generate_password_string(request.size, request.numbers, request.special_char)
    
    encrypted_password = encrypt.encrypt_data(secret_key, password_str)
    
    generated_password = pwd.Password(
        password=encrypted_password,
        expire_at=request.expire_at,
        views_left=request.views_left
    )
    db.add(generated_password)
    db.commit()
    db.refresh(generated_password)
    return generated_password

def created_password(request: pwd.PasswordBase, db: SessionDep):
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption key not configured")  
    encrypted_password = encrypt.encrypt_data(secret_key, request.password)
    
    db_password = pwd.Password(
        password=encrypted_password,
        expire_at=request.expire_at,
        views_left=request.views_left,
    )
    db.add(db_password)
    db.commit()
    db.refresh(db_password)
    return db_password

def get_password_by_token(token: str, db: SessionDep):
    password = db.exec(select(pwd.Password).where(pwd.Password.token_url == token)).first()
    
    if not password:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Password not found")

    current_time = datetime.now()
    if password.expire_at and password.expire_at < current_time:
        db.delete(password)
        db.commit()
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Password has expired")

    if password.views_left is not None:
        if password.views_left <= 0:
            db.delete(password)
            db.commit()
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="No views left")
        elif password.views_left == 1:
            secret_key = os.getenv("SECRET_KEY")
            if not secret_key:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption key not configured")
            decrypted_password = encrypt.decrypt_data(secret_key, password.password)
            password.password = decrypted_password
            password.views_left = 0

            db.delete(password)
            db.commit()
            return password
        else:
            password.views_left -= 1
            db.commit()
            db.refresh(password)

    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Encryption key not configured")
    
    decrypted_password = encrypt.decrypt_data(secret_key, password.password)
    password.password = decrypted_password

    return password

