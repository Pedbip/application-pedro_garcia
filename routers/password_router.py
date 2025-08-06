from fastapi import APIRouter, status, Depends
from repository import password_repo
from models import password as pwd
from utils.database import SessionDep

router = APIRouter(prefix="/share", tags=["users"])

@router.post("/password", response_model=pwd.Password, status_code=status.HTTP_201_CREATED)
async def insert_password(request: pwd.PasswordBase, db: SessionDep):
    return password_repo.created_password(request, db)

@router.post("/generate", response_model=pwd.Password, status_code=status.HTTP_201_CREATED)
async def generate_password(request: pwd.PasswordGen, db: SessionDep):
    return password_repo.generate_secure_password(request, db)

@router.post("/{token}", response_model=pwd.Password, status_code=status.HTTP_200_OK)
async def get_password_by_token(token: str, db: SessionDep):
    return password_repo.get_password_by_token(token, db)