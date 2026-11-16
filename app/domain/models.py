"""领域模型定义（SQLAlchemy ORM）。

模型关系概览：
- User   —— 主体（可代表自然人、服务账号）
- Role   —— 角色，支持层级（parent_id）用于权限继承
- Permission —— 权限点，表示为「资源:动作」（如 order:read）
- RolePermission —— 角色-权限多对多
- UserRole       —— 用户-角色多对多
- Policy —— ABAC 策略，带条件表达式与效果（allow/deny）
- AuditLog —— 决策审计日志
"""
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.infra.database import Base


class TimestampMixin:
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    display_name = Column(String(128))
    email = Column(String(128))
    password_hash = Column(String(256))
    # 主体属性（JSON 字符串），供 ABAC 条件引用，如 {"level": 5, "dept": "eng"}
    attributes = Column(Text, default="{}")
    # 乐观锁版本号
    version = Column(Integer, default=0, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

    roles = relationship("Role", secondary="user_roles", back_populates="users")


class Role(TimestampMixin, Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(256))
    # 父角色，支持角色层级继承
    parent_id = Column(Integer, ForeignKey("roles.id"), nullable=True)
    version = Column(Integer, default=0, nullable=False)

    parent = relationship("Role", remote_side=[id], backref="children")
    permissions = relationship("Permission", secondary="role_permissions", back_populates="roles")
    users = relationship("User", secondary="user_roles", back_populates="roles")


class Permission(TimestampMixin, Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True)
    # 资源标识，如 order、report
    resource = Column(String(64), nullable=False, index=True)
    # 动作，如 read、write、delete，支持通配符 *
    action = Column(String(32), nullable=False)
    description = Column(String(256))

    __table_args__ = (UniqueConstraint("resource", "action", name="uq_perm_resource_action"),)

    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), primary_key=True)


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)


class Policy(TimestampMixin, Base):
    """ABAC 策略：在 RBAC 之外对决策施加条件约束或额外放行/拒绝。

    effect 取值：
      allow —— 满足条件时放行
      deny  —— 满足条件时拒绝（最高优先级，deny-overrides）
    condition 为表达式字符串，例如：
      subject.level >= 3
      resource.owner_id == subject.id
      subject.dept == resource.dept && resource.sensitive == false
    """

    __tablename__ = "policies"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(String(256))
    effect = Column(String(8), nullable=False)  # allow | deny
    # 限制作用范围：空表示任意资源
    resource = Column(String(64), nullable=True)
    action = Column(String(32), nullable=True)
    condition = Column(Text, nullable=False)
    priority = Column(Integer, default=0, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    version = Column(Integer, default=0, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    subject = Column(String(64), index=True)
    resource = Column(String(64), index=True)
    action = Column(String(32))
    decision = Column(String(8))  # allow | deny
    reason = Column(String(256))
    context = Column(Text, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class ModelVersion(Base):
    """权限模型全局版本号：任何模型变更都会递增，用于缓存失效。"""

    __tablename__ = "model_version"

    id = Column(Integer, primary_key=True)
    version = Column(Integer, default=0, nullable=False)
