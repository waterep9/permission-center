"""数据库引擎与会话工厂。"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings

connect_args = {}
engine_kwargs = {}
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    # 内存 SQLite 使用 StaticPool，确保所有会话共享同一连接（测试用）
    if ":memory:" in settings.database_url:
        engine_kwargs = {"poolclass": StaticPool}

engine = create_engine(
    settings.database_url,
    echo=settings.sql_echo,
    connect_args=connect_args,
    future=True,
    **engine_kwargs,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

Base = declarative_base()


def get_db():
    """FastAPI 依赖：提供请求级数据库会话。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
