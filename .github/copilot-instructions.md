# Copilot Instructions for 校园失物招领系统 (Campus Lost & Found)

## 项目架构概览
- **核心框架**：基于 Flask，使用 Flask-SQLAlchemy 进行 ORM，Flask-WTF 提供 CSRF 保护。
- **主要文件**：
  - `app.py`：主入口，包含路由、业务逻辑、会话管理、自动登录、权限控制。
  - `models.py`：定义 `User`、`Item` 等数据库模型。
  - `static/`：静态资源（CSS、图片、上传文件）。
  - `templates/`：Jinja2 模板，页面结构与渲染逻辑。

## 数据模型与权限
- 用户分为普通用户和管理员（`is_admin` 字段）。
- 物品（Item）有三种状态：0-待审核，1-已通过，2-已拒绝，3-已找到。
- 支持“记住我”自动登录，令牌存储于 `RememberToken` 表。

## 路由与页面
- 首页 `/` 展示所有已通过审核的物品。
- 用户注册、登录、发布、查看详情、退出等功能齐全。
- 管理员后台 `/admin_dashboard` 可审核物品，操作 approve/reject。
- 所有页面均继承 `base.html`，统一导航与消息提示。

## 关键开发约定
- **CSRF 保护**：所有表单需包含 `csrf_token`，后端已全局启用 CSRF。
- **图片上传**：上传文件存储于 `static/uploads/`，使用 `secure_filename` 处理。
- **会话管理**：登录状态存于 session，自动登录依赖 Cookie `remember_token`。
- **模板变量**：页面通过 `session.user_id`、`session.is_admin` 判断登录与权限。
- **状态标签**：前端用整数判断物品状态，模板内有 `{% if item.status == 0 %}` 等判断。

## 本地开发与调试
- 数据库通过 `.env` 文件的 `DATABASE_URI` 环境变量配置，支持 MySQL（推荐生产环境使用）和 SQLite。
- 示例：
  ```ini
  DATABASE_URI=mysql+pymysql://root:123456@localhost:3306/campus_lost_found
  ```
  若未设置环境变量，默认回退为 SQLite（`lostfound.db`）。
- 启动命令：`python app.py`（如有 Flask CLI 支持可用 `flask run`）。
- 首次运行需初始化数据库：
  ```python
  from app import db
  db.create_all()
  ```
- 静态资源样式集中于 `static/css/style.css`，页面风格现代简洁。

## 其他说明
- 未发现自动化测试、CI/CD 或特殊构建脚本。
- 若需扩展功能，建议遵循现有 MVC 分层与 Flask 蓝图模式。

---
如需补充说明或有疑问，请在下方补充。