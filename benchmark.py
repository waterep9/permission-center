"""基础压测脚本：对 /decide 接口进行并发与吞吐测试。"""
import json
import time
import urllib.request

BASE = "http://127.0.0.1:8010"


def login():
    body = json.dumps({"username": "admin", "password": "secret123"}).encode()
    req = urllib.request.Request(
        BASE + "/api/v1/auth/login", data=body,
        headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req).read())["access_token"]


def decide(token, user_id, resource, action):
    body = json.dumps({"user_id": user_id, "resource": resource, "action": action}).encode()
    req = urllib.request.Request(
        BASE + "/api/v1/decide", data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    return json.loads(urllib.request.urlopen(req).read())


def main():
    token = login()
    # 预热
    for _ in range(50):
        decide(token, 2, "order", "read")

    # 顺序吞吐测试
    N = 2000
    start = time.time()
    allow = 0
    for _ in range(N):
        r = decide(token, 2, "order", "read")
        allow += r["allow"]
    elapsed = time.time() - start
    print(f"[顺序吞吐] {N} 次决策耗时 {elapsed:.2f}s，QPS≈{N/elapsed:.0f}（allow={allow}）")

    # 不同资源测试（走缓存未命中的路径）
    N2 = 500
    start = time.time()
    for i in range(N2):
        decide(token, 2, f"res_{i % 100}", "read")
    elapsed = time.time() - start
    print(f"[缓存未命中] {N2} 次不同资源决策耗时 {elapsed:.2f}s，QPS≈{N2/elapsed:.0f}")


if __name__ == "__main__":
    main()
