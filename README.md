# 🔐 权限中心（Permission Center）

一个面向微服务与内部系统的 **RBAC + ABAC 混合权限中心**，提供统一的身份、角色、权限点、策略管理与授权决策能力，内置决策引擎、审计日志与决策缓存。

> 定位：作为架构中的「授权决策基础设施」，业务系统通过 `/decide` 接口获得一次授权判定，而不必各自实现权限逻辑。

---

## 一、解决的问题

在企业多系统场景下，权限逻辑常被散落在各业务代码里，导致：

- **规则不一致**：每个服务各自实现 RBAC，语义与漏洞各不相同；
- **难以审计**：谁、在何时、因为什么规则被放行/拒绝，无法统一追踪；
- **策略无法复用**：跨系统的属性级约束（如「仅本人可编辑」「高敏感资源需高级别」）反复造轮子；
- **变更风险高**：改一处权限规则需改多份代码、多次发布。

本系统将授权收敛为**一个独立的决策服务**：

1. **RBAC**：用户 → 角色 → 权限点（`资源:动作`），支持角色层级继承与 `*` 通配；
2. **ABAC**：基于主体/资源/环境属性的条件策略（如 `resource.owner_id == subject_id`），支持 `allow` 与 `deny` 效果；
3. **deny-overrides 语义**：任何命中的 `deny` 策略压过所有 `allow`，符合安全默认拒绝原则；
4. **统一审计**：每次决策落库，可追溯。

---

## 二、架构分层

```
┌─────────────────────────────────────────────────────────┐
│                    接入层 (API / Web)                     │
│   /api/v1/*  REST 接口      / 静态管理控制台              │
├─────────────────────────────────────────────────────────┤
│                     服务层 (Services)                     │
│   decision（决策引擎）   admin（模型管理）  security（认证）│
├─────────────────────────────────────────────────────────┤
│                     核心层 (Core)                         │
│   expression（安全表达式求值器）  config（配置）           │
├─────────────────────────────────────────────────────────┤
│                     领域层 (Domain)                       │
│   User / Role / Permission / Policy / AuditLog           │
│   （RBAC 模型 + ABAC 策略 + 审计实体）                    │
├─────────────────────────────────────────────────────────┤
│                   基础设施层 (Infra)                      │
│   database（SQLAlchemy）  cache（决策缓存 LRU）           │
└─────────────────────────────────────────────────────────┘
```

**目录结构：**

```
permission-center/
├── app/
│   ├── main.py            # FastAPI 入口
│   ├── api/               # 路由 + Pydantic schema
│   ├── core/              # 配置、JWT、表达式求值器
│   ├── domain/            # ORM 模型（领域实体）
│   ├── infra/             # 数据库、缓存
│   └── services/          # 决策引擎、管理服务
├── static/                # Web 管理控制台
├── tests/                 # 单元 + 集成 + 端到端测试
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## 三、关键技术设计

### 1. 权限模型

- **权限点**：`资源:动作`，如 `order:read`、`order:write`；支持 `*` 通配（`order:*`、`*:*`）。
- **角色层级**：角色可指定 `parent_id`，子角色自动继承父角色全部权限（向上递归收集祖先角色）。
- **主体属性**：用户携带 JSON 属性（如 `{"level": 5, "dept": "eng"}`），供 ABAP 条件引用。

### 2. 决策引擎（`decision.py`）

判定顺序：

1. 组装上下文：`subject`（用户属性）、`resource`（资源属性）、`action`、`env`（环境）；
2. **RBAC 判定**：收集用户及其祖先角色的权限点，判断是否命中 `(resource, action)`；
3. **ABAC 策略评估**：按 `priority` 从高到低，`deny` 策略优先；
4. **最终决策**：
   - 命中 `deny` → 拒绝（deny-overrides）；
   - 命中 `allow` → 放行；
   - 否则回退 RBAC 结果。

### 3. 安全表达式求值器（`expression.py`）

ABAC 条件**不使用 Python `eval`**（避免代码注入），而是自研的递归下降解析器，仅支持：

- 字面量：整数、浮点、字符串、布尔、`null`；
- 属性访问：`subject.x` / `resource.y` / `env.z`；
- 比较：`==` `!=` `>` `>=` `<` `<=`；
- 逻辑：`&&` `||` `!`，支持括号与短路。

任何非法字符或危险调用（如 `__class__`）都会被拒绝。

### 4. 决策缓存与失效（`cache.py`）

- 进程内 LRU 缓存，键为 `(user, resource, action, res_attrs)`；
- **全局模型版本号**：任何权限模型变更（建角色/权限/绑定/策略）都会 `bump` 版本；
- 缓存条目携带版本号，版本不匹配即视为失效，**避免脏读**。

### 5. 安全与健壮性

| 关注点 | 实现 |
|--------|------|
| 认证 | JWT（HS256），令牌过期 |
| 越权防护 | 管理接口需 Bearer Token；决策接口需认证 |
| 幂等 | 用户/角色/权限/策略创建前查唯一约束，重复创建返回既有记录 |
| 并发控制 | 用户更新使用 `version` 乐观锁，冲突返回 409 |
| 审计 | 每次决策落 `audit_logs`，含主体/资源/动作/决策/原因/上下文 |
| 容错 | 策略表达式求值异常不崩溃，按「不命中」继续 |

---

## 四、设计取舍

- **SQLite 默认、SQLAlchemy 抽象**：开发零配置即可跑通；生产切换 PostgreSQL 只需改 `DATABASE_URL`。
- **进程内缓存 vs 分布式缓存**：为保持零外部依赖与单机可运行，默认使用进程内 LRU；缓存层已抽象，可替换为 Redis 以支持多实例。
- **RBAC + ABAC 而非纯 ABAC**：纯 ABAC 策略可表达一切，但规则易失控、难调试；保留 RBAC 作为「快速、可读」的主路径，ABAC 处理属性级细粒度约束，二者互补。
- **deny-overrides**：安全领域常见语义，`deny` 策略无条件压过 `allow`，避免「忘记拒绝」的漏洞。

---

## 五、运行步骤

### 本地运行

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 初始化管理员账号（首个用户无法通过 API 创建，需引导种子）
python seed.py                # 默认创建 admin / admin123
python seed.py myuser mypass  # 或指定用户名与密码

# 3. 启动服务
uvicorn app.main:app --reload --port 8000

# 4. 访问
#    API 文档：http://localhost:8000/docs
#    管理控制台：http://localhost:8000/
```

### Docker 运行

```bash
docker compose up --build
```

---

## 六、快速上手示例

```bash
# 1. 创建管理员并登录
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"secret123"}'

# 2. 创建用户（携带属性）
curl -X POST http://localhost:8000/api/v1/users \
  -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"pw123456","attributes":{"level":5}}'

# 3. 创建角色、权限点并绑定
curl -X POST http://localhost:8000/api/v1/roles \
  -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' \
  -d '{"name":"editor"}'

curl -X POST http://localhost:8000/api/v1/permissions \
  -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' \
  -d '{"resource":"order","action":"read"}'

# 4. 执行一次授权决策
curl -X POST http://localhost:8000/api/v1/decide \
  -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' \
  -d '{"user_id":2,"resource":"order","action":"read"}'
```

---

## 七、API 文档

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/auth/login` | 登录获取 JWT |
| POST | `/api/v1/users` | 创建用户（幂等） |
| GET | `/api/v1/users/{id}` | 查询用户 |
| PATCH | `/api/v1/users/{id}` | 更新用户（乐观锁） |
| POST | `/api/v1/roles` | 创建角色 |
| GET | `/api/v1/roles` | 角色列表 |
| POST | `/api/v1/permissions` | 创建权限点 |
| GET | `/api/v1/permissions` | 权限点列表 |
| POST | `/api/v1/bindings/user-role` | 用户绑定角色 |
| DELETE | `/api/v1/bindings/user-role` | 解除用户角色 |
| POST | `/api/v1/bindings/role-permission` | 角色绑定权限 |
| DELETE | `/api/v1/bindings/role-permission` | 解除角色权限 |
| POST | `/api/v1/policies` | 创建 ABAC 策略 |
| GET | `/api/v1/policies` | 策略列表 |
| POST | `/api/v1/decide` | **授权决策（核心）** |
| GET | `/api/v1/audit` | 审计日志 |

完整的请求/响应模型见 `app/api/schemas.py` 与 Swagger（`/docs`）。

---

## 八、测试

```bash
pytest -v
```

覆盖：表达式求值器单元测试、决策引擎集成测试（RBAC/ABAC/通配/层级继承/deny-overrides/缓存失效/审计/停用用户）、API 端到端测试（认证、幂等、完整决策链路）。

## 九、压测

```bash
python benchmark.py
```

对 `/decide` 接口做顺序吞吐测试（缓存命中约 180 QPS、缓存未命中约 120 QPS，单进程串行 + HTTP 往返开销下的基线；生产并发部署可进一步提升）。

## 十、许可

MIT
