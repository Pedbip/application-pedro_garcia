from models import password as pwd
from fastapi import HTTPException, status
from sqlmodel import select
from utils.database import SessionDep
import secrets, string
from datetime import datetime

def generate_secure_password(request: pwd.PasswordGen, db: SessionDep):
    characters = string.ascii_letters
    if request.numbers:
        characters += string.digits
    if request.special_char:
        characters += string.punctuation
    random_password = ''.join(secrets.choice(characters) for _ in range(request.size))
        
    generated_password = pwd.Password(
        encrypted_password=random_password,
        expire_at=request.expire_at,
        views_left=request.views_left
    )
    db.add(generated_password)
    db.commit()
    db.refresh(generated_password)
    return generated_password

def created_password(request: pwd.PasswordBase, db: SessionDep):
    db_password = pwd.Password(
        encrypted_password=request.encrypted_password,
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

    # Check if this specific password has expired or no views left
    current_time = datetime.utcnow()
    if password.expire_at and password.expire_at < current_time:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Password has expired")
    elif password.views_left is not None and password.views_left <= 0:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="No views left for this password")
    
    ## Auto-delete if expired or views are exhausted
    
    
    # Decrease view count if applicable
    if password.views_left is not None and password.views_left > 0:
        password.views_left -= 1
        db.add(password)
        db.commit()
        db.refresh(password)
    
    return password

