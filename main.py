from fastapi import FastAPI
from utils import database
from contextlib import asynccontextmanager
from models import password
from utils.database import Session, engine
from functools import partial
from routers import password_router
from dotenv import load_dotenv

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Criando banco de dados e tabelas...")
    database.create_db_and_tables()
    yield
    print("API sendo encerrada...")
    
    
app = FastAPI(lifespan=lifespan)


app.include_router(password_router.router)