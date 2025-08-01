from fastapi import APIRouter

router = APIRouter(prefix="/share", tags=["users"])

@router.post("/")
async def insert_password():
    pass

@router.post("/")
async def generate_password():
    pass