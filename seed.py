"""初始化脚本：创建初始管理员账号（引导用）。

权限中心的第一个用户无法通过 API 创建（因为创建用户需要登录），
故提供此引导脚本在首次部署时创建种子管理员。

用法：
    python seed.py                # 默认 admin / admin123
    python seed.py myuser mypass  # 自定义用户名与密码
"""
import sys

from app.infra.database import SessionLocal
from app.services import admin


def main():
    username = sys.argv[1] if len(sys.argv) > 1 else "admin"
    password = sys.argv[2] if len(sys.argv) > 2 else "admin123"
    with SessionLocal() as db:
        existing = admin.get_user_by_username(db, username)
        if existing:
            print(f"用户 {username} 已存在，跳过。")
            return
        admin.create_user(db, username, password, display_name="管理员")
        print(f"已创建管理员：{username} / {password}（请立即修改密码）")


if __name__ == "__main__":
    main()
