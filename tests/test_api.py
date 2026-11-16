"""API 端到端测试。"""
from tests.conftest import auth_headers


def test_login_and_health(client):
    assert client.get("/healthz").status_code == 200


def test_login_flow(client, admin_token):
    assert admin_token


def test_unauthenticated_denied(client):
    r = client.get("/api/v1/users/1")
    assert r.status_code == 401


def test_create_user_idempotent(client, admin_token):
    h = auth_headers(admin_token)
    body = {"username": "eve", "password": "pw123456", "display_name": "Eve"}
    r1 = client.post("/api/v1/users", json=body, headers=h)
    assert r1.status_code == 201
    uid = r1.json()["id"]
    # 重复创建应幂等返回同一用户
    r2 = client.post("/api/v1/users", json=body, headers=h)
    assert r2.status_code == 201
    assert r2.json()["id"] == uid


def test_full_decision_via_api(client, admin_token):
    h = auth_headers(admin_token)
    # 建角色、权限、绑定
    role = client.post("/api/v1/roles", json={"name": "api_editor"}, headers=h).json()
    perm = client.post("/api/v1/permissions",
                       json={"resource": "article", "action": "write"}, headers=h).json()
    user = client.post("/api/v1/users",
                       json={"username": "writer", "password": "pw123456"}, headers=h).json()
    client.post("/api/v1/bindings/role-permission",
                json={"role_id": role["id"], "permission_id": perm["id"]}, headers=h)
    client.post("/api/v1/bindings/user-role",
                json={"user_id": user["id"], "role_id": role["id"]}, headers=h)

    r = client.post("/api/v1/decide",
                    json={"user_id": user["id"], "resource": "article", "action": "write"},
                    headers=h)
    assert r.status_code == 200
    assert r.json()["allow"] is True


def test_audit_endpoint(client, admin_token):
    h = auth_headers(admin_token)
    r = client.get("/api/v1/audit?limit=10", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_policy_validation(client, admin_token):
    h = auth_headers(admin_token)
    # 非法 effect 应被拒绝
    r = client.post("/api/v1/policies",
                    json={"name": "bad", "effect": "maybe", "condition": "true"}, headers=h)
    assert r.status_code == 422
