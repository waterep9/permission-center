"""REST API 路由。"""
import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api import schemas
from app.core.security import create_token, get_current_user
from app.services.admin import verify_password
from app.domain import models
from app.infra.database import get_db
from app.services import admin, decision
from app.services.admin import ConflictError

router = APIRouter()


def _attrs_to_dict(user: models.User) -> dict:
    try:
        return json.loads(user.attributes or "{}")
    except json.JSONDecodeError:
        return {}


# ---------- 认证 ----------
@router.post("/auth/login", response_model=schemas.TokenResponse, tags=["认证"])
def login(req: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = admin.get_user_by_username(db, req.username)
    if user is None or not verify_password(req.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
    if not user.enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "账号已停用")
    return {"access_token": create_token(user.id, user.username)}


# ---------- 用户 ----------
@router.post("/users", response_model=schemas.UserOut, status_code=201, tags=["用户"])
def create_user(req: schemas.UserCreate, db: Session = Depends(get_db),
                _=Depends(get_current_user)):
    user = admin.create_user(db, req.username, req.password, req.display_name,
                             req.email, req.attributes)
    return _serialize_user(user)


@router.get("/users/{user_id}", response_model=schemas.UserOut, tags=["用户"])
def get_user(user_id: int, db: Session = Depends(get_db), _=Depends(get_current_user)):
    user = admin.get_user(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    return _serialize_user(user)


@router.patch("/users/{user_id}", response_model=schemas.UserOut, tags=["用户"])
def update_user(user_id: int, req: schemas.UserUpdate, db: Session = Depends(get_db),
                _=Depends(get_current_user)):
    user = admin.get_user(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    try:
        user = admin.update_user(
            db, user_id, version=user.version,
            display_name=req.display_name, email=req.email,
            attributes=req.attributes, enabled=req.enabled,
        )
    except ConflictError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e))
    return _serialize_user(user)


# ---------- 角色 ----------
@router.post("/roles", response_model=schemas.RoleOut, status_code=201, tags=["角色"])
def create_role(req: schemas.RoleCreate, db: Session = Depends(get_db),
                _=Depends(get_current_user)):
    role = admin.create_role(db, req.name, req.description, req.parent_id)
    return role


@router.get("/roles", response_model=list[schemas.RoleOut], tags=["角色"])
def list_roles(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(models.Role).all()


# ---------- 权限 ----------
@router.post("/permissions", response_model=schemas.PermissionOut, status_code=201, tags=["权限"])
def create_permission(req: schemas.PermissionCreate, db: Session = Depends(get_db),
                      _=Depends(get_current_user)):
    perm = admin.create_permission(db, req.resource, req.action, req.description)
    return perm


@router.get("/permissions", response_model=list[schemas.PermissionOut], tags=["权限"])
def list_permissions(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return db.query(models.Permission).all()


# ---------- 绑定 ----------
@router.post("/bindings/user-role", tags=["绑定"])
def bind_user_role(req: schemas.RoleBindingRequest, db: Session = Depends(get_db),
                   _=Depends(get_current_user)):
    try:
        admin.bind_role_to_user(db, req.user_id, req.role_id)
    except ConflictError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    return {"ok": True}


@router.delete("/bindings/user-role", tags=["绑定"])
def unbind_user_role(req: schemas.RoleBindingRequest, db: Session = Depends(get_db),
                     _=Depends(get_current_user)):
    try:
        admin.unbind_role_from_user(db, req.user_id, req.role_id)
    except ConflictError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    return {"ok": True}


@router.post("/bindings/role-permission", tags=["绑定"])
def bind_role_permission(req: schemas.RolePermissionRequest, db: Session = Depends(get_db),
                         _=Depends(get_current_user)):
    try:
        admin.bind_permission_to_role(db, req.role_id, req.permission_id)
    except ConflictError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    return {"ok": True}


@router.delete("/bindings/role-permission", tags=["绑定"])
def unbind_role_permission(req: schemas.RolePermissionRequest, db: Session = Depends(get_db),
                           _=Depends(get_current_user)):
    try:
        admin.unbind_permission_from_role(db, req.role_id, req.permission_id)
    except ConflictError as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(e))
    return {"ok": True}


# ---------- 策略 ----------
@router.post("/policies", response_model=schemas.PolicyOut, status_code=201, tags=["策略"])
def create_policy(req: schemas.PolicyCreate, db: Session = Depends(get_db),
                  _=Depends(get_current_user)):
    policy = admin.create_policy(db, req.name, req.effect, req.condition,
                                 req.resource, req.action, req.description, req.priority)
    return policy


@router.get("/policies", response_model=list[schemas.PolicyOut], tags=["策略"])
def list_policies(db: Session = Depends(get_db), _=Depends(get_current_user)):
    return admin.list_policies(db)


# ---------- 决策 ----------
@router.post("/decide", response_model=schemas.DecisionResponse, tags=["决策"])
def decide(req: schemas.DecisionRequest, db: Session = Depends(get_db),
           _=Depends(get_current_user)):
    user = admin.get_user(db, req.user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    return decision.decide(db, user, req.resource, req.action,
                           req.resource_attributes, req.environment)


# ---------- 审计 ----------
@router.get("/audit", response_model=list[schemas.AuditOut], tags=["审计"])
def list_audit(limit: int = 100, db: Session = Depends(get_db),
               _=Depends(get_current_user)):
    rows = (
        db.query(models.AuditLog)
        .order_by(models.AuditLog.id.desc())
        .limit(min(limit, 500))
        .all()
    )
    return [
        schemas.AuditOut(
            id=r.id, subject=r.subject, resource=r.resource, action=r.action,
            decision=r.decision, reason=r.reason, created_at=r.created_at.isoformat(),
        )
        for r in rows
    ]


def _serialize_user(user: models.User) -> schemas.UserOut:
    return schemas.UserOut(
        id=user.id, username=user.username, display_name=user.display_name,
        email=user.email, attributes=_attrs_to_dict(user), enabled=user.enabled,
        roles=[r.name for r in user.roles],
    )
