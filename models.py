# 导入SQLAlchemy用于ORM，datetime用于时间戳，werkzeug用于密码加密校验
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# 初始化数据库对象（由app.py实际初始化）
db = SQLAlchemy()

# 用户表模型，包含普通用户和管理员
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    username = db.Column(db.String(50), unique=True, nullable=False)  # 用户名，唯一
    email = db.Column(db.String(100), unique=True, nullable=False)  # 邮箱，唯一
    password_hash = db.Column(db.String(255), nullable=False)  # 密码哈希
    is_admin = db.Column(db.Boolean, default=False)  # 是否为管理员
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 创建时间

    # 设置密码（加密存储）
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 校验密码
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 物品表模型，记录失物/招领信息
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 主键
    title = db.Column(db.String(100), nullable=False)  # 物品名称
    description = db.Column(db.Text, nullable=False)  # 物品描述
    place = db.Column(db.String(100), nullable=False)  # 拾取/丢失地点
    time = db.Column(db.DateTime, nullable=False)  # 丢失/拾取时间
    contact = db.Column(db.String(100), nullable=False)  # 联系方式
    image = db.Column(db.String(255))  # 图片路径
    status = db.Column(db.Integer, default=0)  # 状态：0-待审核 1-已通过 2-已拒绝 3-已找到
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 发布人ID
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # 发布时间

    # 关联用户
    user = db.relationship('User', backref=db.backref('items', lazy=True))