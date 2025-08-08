import logging
import os

if os.getenv("DISABLE_SQLALCHEMY_LOGS", "false").lower() == "true":
    logging.getLogger("sqlalchemy.engine").disabled = True
    logging.getLogger("sqlalchemy.pool").disabled = True
    logging.getLogger("sqlalchemy").disabled = True
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, Request, Depends
from utils import database
from contextlib import asynccontextmanager
from models import audit_log as log
from utils.database import async_session_maker
from routers import password_router
from datetime import datetime, timezone

from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Criando banco de dados e tabelas...")
    await database.create_db_and_tables()

    redis_url = os.getenv("REDIS_URL")
    r = redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(r)

    yield
    logging.info("API sendo encerrada...")


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)  

cors_origins = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:8000")
allow_origins = [origin.strip() for origin in cors_origins.split(",")]

class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host
        method = request.method
        path = request.url.path
        timestamp = datetime.now(timezone.utc)
        user_agent = request.headers.get("user-agent")

        try:
            async with async_session_maker() as session:
                audit_entry = log.AuditLog(
                    ip=ip,
                    method=method,
                    path=path,
                    timestamp=timestamp,
                    user_agent=user_agent,
                )
                session.add(audit_entry)
                await session.commit()  
        except Exception as e:
            logging.error(f"Erro ao salvar log de auditoria: {e}")

        response = await call_next(request)
        return response

app.add_middleware(AuditMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

app.add_middleware(HTTPSRedirectMiddleware)

trusted_hosts_env = os.getenv("TRUSTED_HOSTS", "seu-dominio.com,localhost,127.0.0.1")
allowed_hosts = [host.strip() for host in trusted_hosts_env.split(",")]

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

app.include_router(
    password_router.router,
    dependencies=[Depends(RateLimiter(times=5, seconds=60))]
)

