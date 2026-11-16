"""应用配置：通过环境变量或 .env 覆盖，便于本地与容器化部署。"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "权限中心 (Permission Center)"
    app_version: str = "1.0.0"
    # 数据库连接串，默认使用本地 SQLite，可切换 PostgreSQL：
    #   postgresql+psycopg://user:pass@host:5432/perm
    database_url: str = "sqlite:///./permission.db"
    # 是否回显 SQL（调试用）
    sql_echo: bool = False
    # JWT 签名密钥（生产环境务必通过环境变量覆盖）
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    token_ttl_minutes: int = 60
    # 权限决策缓存开关与容量（进程内 LRU）
    cache_enabled: bool = True
    cache_capacity: int = 4096
    # 审计日志落库开关
    audit_enabled: bool = True

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
