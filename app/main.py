"""FastAPI 应用入口。"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import settings
from app.domain import models
from app.infra.database import Base, engine


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="RBAC + ABAC 混合权限中心：决策引擎、策略评估、审计与缓存",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 初始化数据库表
    Base.metadata.create_all(bind=engine)
    _ensure_model_version()

    app.include_router(router, prefix="/api/v1")

    @app.get("/healthz", tags=["系统"])
    def healthz():
        return {"status": "ok", "version": settings.app_version}

    # 挂载管理界面静态资源（置于所有 API 路由之后，作为兜底）
    app.mount("/", StaticFiles(directory="static", html=True), name="static")

    return app


def _ensure_model_version():
    from sqlalchemy.orm import Session
    from app.infra.database import SessionLocal

    with SessionLocal() as db:
        if db.query(models.ModelVersion).count() == 0:
            db.add(models.ModelVersion(version=0))
            db.commit()


app = create_app()
