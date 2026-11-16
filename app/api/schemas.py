"""API 请求/响应模型（Pydantic）。"""
from typing import Optional

from pydantic import BaseModel, Field


# ---------- 认证 ----------
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------- 用户 ----------
class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: Optional[str] = None
    email: Optional[str] = None
    password: str
    attributes: dict = Field(default_factory=dict)


class UserUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    attributes: Optional[dict] = None
    enabled: Optional[bool] = None


class UserOut(BaseModel):
    id: int
    username: str
    display_name: Optional[str]
    email: Optional[str]
    attributes: dict
    enabled: bool
    roles: list[str] = []

    class Config:
        from_attributes = True


# ---------- 角色 ----------
class RoleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: Optional[str] = None
    parent_id: Optional[int] = None


class RoleOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    parent_id: Optional[int]

    class Config:
        from_attributes = True


# ---------- 权限 ----------
class PermissionCreate(BaseModel):
    resource: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=32)
    description: Optional[str] = None


class PermissionOut(BaseModel):
    id: int
    resource: str
    action: str
    description: Optional[str]

    class Config:
        from_attributes = True


# ---------- 绑定 ----------
class RoleBindingRequest(BaseModel):
    user_id: int
    role_id: int


class RolePermissionRequest(BaseModel):
    role_id: int
    permission_id: int


# ---------- 策略 ----------
class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: Optional[str] = None
    effect: str = Field(pattern="^(allow|deny)$")
    resource: Optional[str] = None
    action: Optional[str] = None
    condition: str
    priority: int = 0


class PolicyOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    effect: str
    resource: Optional[str]
    action: Optional[str]
    condition: str
    priority: int
    enabled: bool

    class Config:
        from_attributes = True


# ---------- 决策 ----------
class DecisionRequest(BaseModel):
    user_id: int
    resource: str
    action: str
    resource_attributes: dict = Field(default_factory=dict)
    environment: dict = Field(default_factory=dict)


class DecisionResponse(BaseModel):
    allow: bool
    reason: str
    matched_roles: list[str]
    matched_policies: list[str]


# ---------- 审计 ----------
class AuditOut(BaseModel):
    id: int
    subject: str
    resource: str
    action: str
    decision: str
    reason: str
    created_at: str

    class Config:
        from_attributes = True
