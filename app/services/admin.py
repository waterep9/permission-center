"""用户、角色、权限、策略的管理服务。

关键设计：
- 幂等：创建前检查唯一约束（username / role name / policy name / 资源动作），
  已存在则返回既有记录而非报错；
- 乐观锁：更新用户/角色/策略时校验 version，冲突则抛出并发冲突；
- 模型变更：任何权限模型变更都 bump 全局版本，触发决策缓存失效。
"""
from typing import Optional

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.domain import models
from app.services.decision import bump_model_version

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class ConflictError(Exception):
    pass


def hash_password(raw: str) -> str:
    return pwd_context.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    return pwd_context.verify(raw, hashed)


# ---------- 用户 ----------
def create_user(db: Session, username: str, password: str,
                display_name=None, email=None, attributes=None) -> models.User:
    existing = db.query(models.User).filter(models.User.username == username).first()
    if existing:
        return existing  # 幂等
    user = models.User(
        username=username,
        display_name=display_name,
        email=email,
        password_hash=hash_password(password),
        attributes=str(attributes or {}).replace("'", '"'),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user(db: Session, user_id: int) -> Optional[models.User]:
    return db.query(models.User).get(user_id)


def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.username == username).first()


def update_user(db: Session, user_id: int, *, version: int, **fields) -> models.User:
    user = get_user(db, user_id)
    if user is None:
        raise ConflictError("用户不存在")
    if user.version != version:
        raise ConflictError("用户已被并发修改，请重试")
    for k, v in fields.items():
        if v is None:
            continue
        if k == "attributes":
            v = str(v).replace("'", '"')
        setattr(user, k, v)
    user.version += 1
    db.commit()
    db.refresh(user)
    bump_model_version(db)
    return user


# ---------- 角色 ----------
def create_role(db: Session, name: str, description=None, parent_id=None) -> models.Role:
    existing = db.query(models.Role).filter(models.Role.name == name).first()
    if existing:
        return existing
    role = models.Role(name=name, description=description, parent_id=parent_id)
    db.add(role)
    db.commit()
    db.refresh(role)
    bump_model_version(db)
    return role


def get_role(db: Session, role_id: int) -> Optional[models.Role]:
    return db.query(models.Role).get(role_id)


# ---------- 权限 ----------
def create_permission(db: Session, resource: str, action: str, description=None) -> models.Permission:
    existing = (
        db.query(models.Permission)
        .filter(models.Permission.resource == resource, models.Permission.action == action)
        .first()
    )
    if existing:
        return existing
    perm = models.Permission(resource=resource, action=action, description=description)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    bump_model_version(db)
    return perm


def get_permission(db: Session, perm_id: int) -> Optional[models.Permission]:
    return db.query(models.Permission).get(perm_id)


# ---------- 绑定 ----------
def bind_role_to_user(db: Session, user_id: int, role_id: int):
    user = get_user(db, user_id)
    role = get_role(db, role_id)
    if user is None or role is None:
        raise ConflictError("用户或角色不存在")
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
        bump_model_version(db)


def unbind_role_from_user(db: Session, user_id: int, role_id: int):
    user = get_user(db, user_id)
    role = get_role(db, role_id)
    if user is None or role is None:
        raise ConflictError("用户或角色不存在")
    if role in user.roles:
        user.roles.remove(role)
        db.commit()
        bump_model_version(db)


def bind_permission_to_role(db: Session, role_id: int, permission_id: int):
    role = get_role(db, role_id)
    perm = get_permission(db, permission_id)
    if role is None or perm is None:
        raise ConflictError("角色或权限不存在")
    if perm not in role.permissions:
        role.permissions.append(perm)
        db.commit()
        bump_model_version(db)


def unbind_permission_from_role(db: Session, role_id: int, permission_id: int):
    role = get_role(db, role_id)
    perm = get_permission(db, permission_id)
    if role is None or perm is None:
        raise ConflictError("角色或权限不存在")
    if perm in role.permissions:
        role.permissions.remove(perm)
        db.commit()
        bump_model_version(db)


# ---------- 策略 ----------
def create_policy(db: Session, name: str, effect: str, condition: str,
                  resource=None, action=None, description=None, priority=0) -> models.Policy:
    existing = db.query(models.Policy).filter(models.Policy.name == name).first()
    if existing:
        return existing
    policy = models.Policy(
        name=name, effect=effect, condition=condition,
        resource=resource, action=action, description=description, priority=priority,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    bump_model_version(db)
    return policy


def list_policies(db: Session):
    return db.query(models.Policy).order_by(models.Policy.priority.desc()).all()
