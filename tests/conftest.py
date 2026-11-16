"""pytest 配置与共享 fixtures。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 测试使用内存 SQLite，避免污染本地数据库
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=True)
def _clean_db():
    """每个测试前清空数据库与决策缓存，避免跨测试状态污染。"""
    from app.domain import models
    from app.infra.cache import decision_cache
    from app.infra.database import SessionLocal

    decision_cache.invalidate()
    with SessionLocal() as db:
        for table in reversed(models.Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_token(client):
    # 创建管理员用户并登录
    from app.infra.database import SessionLocal
    from app.services import admin

    with SessionLocal() as db:
        admin.create_user(db, "admin", "secret123", display_name="管理员")
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret123"})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}
