"""权限决策引擎集成测试：覆盖 RBAC、ABAC、deny-overrides、缓存、审计。"""
import json

from app.infra.database import SessionLocal
from app.services import admin, decision


def _mk_user(db, name="alice", attrs=None):
    return admin.create_user(db, name, "pw123456", attributes=attrs)


def _mk_role(db, name):
    return admin.create_role(db, name)


def _mk_perm(db, resource, action):
    return admin.create_permission(db, resource, action)


def test_rbac_basic_allow():
    with SessionLocal() as db:
        u = _mk_user(db)
        r = _mk_role(db, "viewer")
        p = _mk_perm(db, "order", "read")
        admin.bind_permission_to_role(db, r.id, p.id)
        admin.bind_role_to_user(db, u.id, r.id)

        res = decision.decide(db, u, "order", "read")
        assert res["allow"] is True
        assert res["reason"] == "rbac"
        assert "viewer" in res["matched_roles"]


def test_rbac_deny_without_permission():
    with SessionLocal() as db:
        u = _mk_user(db)
        res = decision.decide(db, u, "order", "write")
        assert res["allow"] is False
        assert res["reason"] == "no_permission"


def test_rbac_wildcard():
    with SessionLocal() as db:
        u = _mk_user(db)
        r = _mk_role(db, "admin")
        p = _mk_perm(db, "*", "*")
        admin.bind_permission_to_role(db, r.id, p.id)
        admin.bind_role_to_user(db, u.id, r.id)

        assert decision.decide(db, u, "anything", "whatever")["allow"] is True


def test_role_hierarchy_inheritance():
    with SessionLocal() as db:
        parent = _mk_role(db, "editor")
        child = _mk_role(db, "senior_editor")
        # 手动设置父子关系
        child.parent_id = parent.id
        db.commit()
        p = _mk_perm(db, "doc", "write")
        admin.bind_permission_to_role(db, parent.id, p.id)

        u = _mk_user(db)
        admin.bind_role_to_user(db, u.id, child.id)

        res = decision.decide(db, u, "doc", "write")
        assert res["allow"] is True


def test_abac_deny_overrides():
    with SessionLocal() as db:
        u = _mk_user(db, attrs={"level": 2})
        r = _mk_role(db, "editor")
        p = _mk_perm(db, "report", "write")
        admin.bind_permission_to_role(db, r.id, p.id)
        admin.bind_role_to_user(db, u.id, r.id)

        # deny 策略：level < 3 的用户不能写 report
        admin.create_policy(db, "low-level-deny", "deny",
                            "subject.level < 3", resource="report", action="write")

        res = decision.decide(db, u, "report", "write")
        assert res["allow"] is False
        assert "low-level-deny" in res["reason"]


def test_abac_allow_policy():
    with SessionLocal() as db:
        u = _mk_user(db, attrs={"dept": "security"})
        # 用户没有任何 RBAC 角色，但 allow 策略放行
        admin.create_policy(db, "security-team-allow", "allow",
                            "subject.dept == 'security'", resource="audit", action="read")

        res = decision.decide(db, u, "audit", "read")
        assert res["allow"] is True
        assert "security-team-allow" in res["reason"]


def test_ownership_abac():
    with SessionLocal() as db:
        u = _mk_user(db, attrs={})
        # 资源 owner 与主体一致才允许（owner 判断由资源属性提供）
        admin.create_policy(db, "owner-allow", "allow",
                            "resource.owner_id == subject_id", resource="doc", action="edit")

        res_own = decision.decide(db, u, "doc", "edit", res_attrs={"owner_id": u.id})
        assert res_own["allow"] is True

        res_other = decision.decide(db, u, "doc", "edit", res_attrs={"owner_id": 999})
        assert res_other["allow"] is False


def test_audit_log_written():
    with SessionLocal() as db:
        u = _mk_user(db, "bob")
        decision.decide(db, u, "order", "read")
        logs = db.query(__import__("app.domain.models", fromlist=["AuditLog"]).AuditLog).filter_by(subject="bob").all()
        assert len(logs) >= 1
        assert logs[-1].decision in ("allow", "deny")


def test_cache_invalidated_on_model_change():
    with SessionLocal() as db:
        u = _mk_user(db, "carol")
        # 首次无权限
        assert decision.decide(db, u, "order", "read")["allow"] is False
        # 授予权限（会 bump 版本）
        r = _mk_role(db, "reader")
        p = _mk_perm(db, "order", "read")
        admin.bind_permission_to_role(db, r.id, p.id)
        admin.bind_role_to_user(db, u.id, r.id)
        # 缓存应失效，重新判定为 allow
        assert decision.decide(db, u, "order", "read")["allow"] is True


def test_disabled_user_denied():
    with SessionLocal() as db:
        u = _mk_user(db, "dave")
        r = _mk_role(db, "admin2")
        p = _mk_perm(db, "*", "*")
        admin.bind_permission_to_role(db, r.id, p.id)
        admin.bind_role_to_user(db, u.id, r.id)
        u.enabled = False
        db.commit()

        res = decision.decide(db, u, "order", "read")
        assert res["allow"] is False
        assert res["reason"] == "subject_disabled"
