"""权限决策引擎：RBAC + ABAC 混合判定，deny-overrides 语义。

判定流程：
1. 组装主体（用户）、资源、动作、环境的上下文；
2. 计算 RBAC 授权：用户通过其角色（含角色层级继承）获得权限点集合，
   判断是否命中 (resource, action)，支持通配符；
3. 计算 ABAC 策略：按 priority 排序，deny 策略优先；
4. 最终决策：
   - 若任一 deny 策略命中 -> 拒绝（deny-overrides）
   - 若有 allow 策略命中 -> 放行
   - 否则回退到 RBAC 结果。

每个判定都写入审计日志，并按模型版本缓存结果。
"""
import json
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.core.expression import evaluate, ExprError
from app.domain import models
from app.infra.cache import decision_cache


class DecisionError(Exception):
    pass


def get_model_version(db: Session) -> int:
    row = db.query(models.ModelVersion).order_by(models.ModelVersion.id.desc()).first()
    return row.version if row else 0


def bump_model_version(db: Session) -> int:
    row = models.ModelVersion(version=get_model_version(db) + 1)
    db.add(row)
    db.commit()
    return row.version


def _collect_role_ids(role: models.Role, seen: set):
    """收集角色自身及其所有祖先角色 id，用于层级继承。"""
    if role.id in seen:
        return
    seen.add(role.id)
    parent = role.parent
    while parent is not None:
        if parent.id in seen:
            break
        seen.add(parent.id)
        parent = parent.parent


def _rbac_permissions(db: Session, user: models.User) -> set:
    """返回用户通过角色获得的权限点集合 (resource, action)。"""
    perm_set = set()
    role_ids = set()
    for role in user.roles:
        _collect_role_ids(role, role_ids)
    if not role_ids:
        return perm_set
    rows = (
        db.query(models.Permission)
        .join(models.RolePermission)
        .filter(models.RolePermission.role_id.in_(role_ids))
        .all()
    )
    for p in rows:
        perm_set.add((p.resource, p.action))
    return perm_set


def _rbac_match(perm_set: set, resource: str, action: str) -> bool:
    """判断权限集合是否命中，支持 * 通配。"""
    if (resource, action) in perm_set:
        return True
    if (resource, "*") in perm_set:
        return True
    if ("*", action) in perm_set:
        return True
    if ("*", "*") in perm_set:
        return True
    return False


def _parse_attrs(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _evaluate_policies(db: Session, subject: models.User, resource: str,
                       action: str, res_attrs: Dict[str, Any],
                       env_attrs: Dict[str, Any]):
    """评估 ABAC 策略，返回 (denied, allowed, reason)。"""
    policies = (
        db.query(models.Policy)
        .filter(models.Policy.enabled.is_(True))
        .order_by(models.Policy.priority.desc())
        .all()
    )
    subject_attrs = _parse_attrs(subject.attributes)
    ctx = {
        "subject": subject_attrs,
        "subject_id": subject.id,
        "resource": res_attrs,
        "action": action,
        "env": env_attrs,
    }
    denied = None
    allowed = None
    for p in policies:
        # 范围过滤
        if p.resource and p.resource != resource:
            continue
        if p.action and p.action != action:
            continue
        try:
            hit = evaluate(p.condition, ctx)
        except ExprError as e:
            # 策略表达式错误不应导致系统崩溃，记录为不命中并继续
            continue
        if not hit:
            continue
        if p.effect == "deny":
            denied = p
            break  # deny 最高优先级，一旦命中即拒绝
        elif p.effect == "allow" and allowed is None:
            allowed = p
    return denied, allowed


def decide(db: Session, subject: models.User, resource: str, action: str,
           res_attrs: Optional[Dict[str, Any]] = None,
           env_attrs: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """核心判定入口，返回决策结果字典。

    返回字段：allow, reason, matched_roles, matched_policies
    """
    res_attrs = res_attrs or {}
    env_attrs = env_attrs or {}

    if not subject.enabled:
        result = {"allow": False, "reason": "subject_disabled",
                  "matched_roles": [], "matched_policies": []}
        _audit(db, subject, resource, action, result, res_attrs, env_attrs)
        return result

    version = get_model_version(db)
    cache_key = f"{subject.id}:{resource}:{action}:{json.dumps(res_attrs, sort_keys=True)}"

    cached = decision_cache.get(cache_key, version)
    if cached is not None:
        return cached

    perm_set = _rbac_permissions(db, subject)
    rbac_allow = _rbac_match(perm_set, resource, action)

    denied, allowed = _evaluate_policies(db, subject, resource, action, res_attrs, env_attrs)

    if denied is not None:
        allow = False
        reason = f"deny_policy:{denied.name}"
    elif allowed is not None:
        allow = True
        reason = f"allow_policy:{allowed.name}"
    elif rbac_allow:
        allow = True
        reason = "rbac"
    else:
        allow = False
        reason = "no_permission"

    result = {
        "allow": allow,
        "reason": reason,
        "matched_roles": [r.name for r in subject.roles],
        "matched_policies": [p.name for p in [denied, allowed] if p],
    }

    decision_cache.put(cache_key, version, result)
    _audit(db, subject, resource, action, result, res_attrs, env_attrs)
    return result


def _audit(db: Session, subject: models.User, resource: str, action: str,
           result: Dict[str, Any], res_attrs: Dict[str, Any],
           env_attrs: Dict[str, Any]):
    """写入审计日志（可配置关闭）。"""
    from app.core.config import settings
    if not settings.audit_enabled:
        return
    log = models.AuditLog(
        subject=subject.username,
        resource=resource,
        action=action,
        decision="allow" if result["allow"] else "deny",
        reason=result["reason"],
        context=json.dumps({"res_attrs": res_attrs, "env_attrs": env_attrs},
                           ensure_ascii=False),
    )
    db.add(log)
    db.commit()
