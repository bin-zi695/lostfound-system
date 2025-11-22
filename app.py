from flask import Flask, render_template, redirect, url_for, request, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import uuid  # 新增：用于生成唯一令牌
from dotenv import load_dotenv
from datetime import datetime, timedelta  # 新增：处理时间和过期
from flask_wtf import CSRFProtect

# 加载环境变量
load_dotenv()

# 初始化Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-for-testing')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lostfound.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 初始化CSRF保护
csrf = CSRFProtect(app)

# 初始化数据库
db = SQLAlchemy(app)


# 数据模型合并自 models.py
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('Item', backref='user', lazy=True)
    remember_tokens = db.relationship('RememberToken', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    place = db.Column(db.String(100), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    contact = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(255))
    status = db.Column(db.Integer, default=0)  # 0-待审核、1-已通过、2-已拒绝、3-已找到
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# 记住登录令牌模型
class RememberToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expire_time = db.Column(db.DateTime, nullable=False)

# 登录验证装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 管理员权限装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('需要管理员权限', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

#请求前检查记住令牌（实现自动登录）
@app.before_request
def check_remember_token():
    # 如果用户未登录但有remember_token Cookie
    if 'user_id' not in session and 'remember_token' in request.cookies:
        token = request.cookies['remember_token']
        # 查询令牌是否有效
        remember_token = RememberToken.query.filter_by(token=token).first()
        if remember_token and remember_token.expire_time > datetime.now():
            # 恢复登录状态
            session['user_id'] = remember_token.user_id
            session['is_admin'] = remember_token.user.is_admin
            # 刷新令牌有效期（每次访问延长7天）
            remember_token.expire_time = datetime.now() + timedelta(days=7)
            db.session.commit()

# 路由定义
@app.route('/')
def index():
    items = Item.query.filter_by(status=1).order_by(Item.created_at.desc()).all()
    return render_template('index.html', items=items)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('两次输入的密码不一致', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('邮箱已存在', 'danger')
            return render_template('register.html')

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            flash('登录成功', 'success')

            #"记住我"功能
            if request.form.get('remember'):  # 检查是否勾选
                # 生成唯一令牌
                token = str(uuid.uuid4())
                # 设置7天过期
                expire_time = datetime.now() + timedelta(days=7)
                # 存储令牌
                new_token = RememberToken(
                    token=token,
                    user_id=user.id,
                    expire_time=expire_time
                )
                db.session.add(new_token)
                db.session.commit()
                # 设置Cookie
                response = make_response(redirect(url_for('index')))
                response.set_cookie(
                    'remember_token',
                    token,
                    max_age=60*60*24*7,  # 7天有效期
                    httponly=True  # 安全设置
                )
                return response

            return redirect(url_for('index'))
        else:
            flash('邮箱或密码错误', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    # 清除session
    session.pop('user_id', None)
    session.pop('is_admin', None)
    
    # 清除记住令牌
    if 'remember_token' in request.cookies:
        token = request.cookies['remember_token']
        remember_token = RememberToken.query.filter_by(token=token).first()
        if remember_token:
            db.session.delete(remember_token)
            db.session.commit()
    # 清除Cookie
    response = make_response(redirect(url_for('index')))
    response.set_cookie('remember_token', '', expires=0)
    
    flash('已成功登出', 'info')
    return response

@app.route('/publish', methods=['GET', 'POST'])
@login_required
def publish():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        place = request.form['place']
        time_str = request.form['time']
        contact = request.form['contact']
        image = request.files['image']

        if not all([title, description, place, time_str, contact]):
            flash('请填写完整信息', 'danger')
            return render_template('publish.html')

        try:
            time = datetime.strptime(time_str, '%Y-%m-%d')
        except ValueError:
            flash('时间格式错误', 'danger')
            return render_template('publish.html')

        filename = None
        if image and image.filename:
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            if '.' in image.filename and image.filename.rsplit('.', 1)[1].lower() in allowed_extensions:
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                flash('仅支持png、jpg、jpeg、gif格式的图片', 'danger')
                return render_template('publish.html')

        item = Item(
            title=title,
            description=description,
            place=place,
            time=time,
            contact=contact,
            image=filename,
            status=0,
            user_id=session['user_id']
        )
        db.session.add(item)
        db.session.commit()
        
        flash('物品发布成功，等待管理员审核', 'success')
        return redirect(url_for('index'))
    return render_template('publish.html')

@app.route('/item/<int:item_id>')
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item_detail.html', item=item)

@app.route('/admin')
@admin_required
def admin_dashboard():
    pending_items = Item.query.filter_by(status=0).all()
    # 统计“已通过”数时应包括已找到前的已通过
    approved_items = Item.query.filter(Item.status.in_([1,3])).all()
    # 但展示时仍需分开
    approved_only = Item.query.filter_by(status=1).all()
    rejected_items = Item.query.filter_by(status=2).all()
    found_items = Item.query.filter_by(status=3).all()
    return render_template('admin_dashboard.html', 
                           pending=pending_items, 
                           approved=approved_only, 
                           rejected=rejected_items,
                           found=found_items,
                           approved_total=len(approved_items))
# 用户查看自己发布的物品及操作（已找到/删除）
@app.route('/user/publish')
@login_required
def user_publish():
    user_id = session['user_id']
    items = Item.query.filter_by(user_id=user_id).order_by(Item.created_at.desc()).all()
    return render_template('user_publish.html', items=items)

# 用户标记物品为已找到
@app.route('/item/<int:item_id>/found', methods=['POST'])
@login_required
def mark_found(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash('无权操作', 'danger')
        return redirect(url_for('user_publish'))
    item.status = 3
    db.session.commit()
    flash('已标记为已找到', 'success')
    return redirect(url_for('user_publish'))

# 用户删除自己发布的物品
@app.route('/item/<int:item_id>/delete', methods=['POST'])
@login_required
def user_delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != session['user_id']:
        flash('无权操作', 'danger')
        return redirect(url_for('user_publish'))
    if item.image:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], item.image)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(item)
    db.session.commit()
    flash('物品已删除', 'info')
    return redirect(url_for('user_publish'))

@app.route('/admin/item/<int:item_id>/approve', methods=['POST'])
@admin_required
def approve_item(item_id):
    item = Item.query.get_or_404(item_id)
    item.status = 1
    db.session.commit()
    flash('物品已通过审核', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/item/<int:item_id>/reject', methods=['POST'])
@admin_required
def reject_item(item_id):
    item = Item.query.get_or_404(item_id)
    item.status = 2
    db.session.commit()
    flash('物品已拒绝审核', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/item/<int:item_id>/delete', methods=['POST'])
@admin_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.image:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], item.image)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(item)
    db.session.commit()
    flash('物品已删除', 'info')
    return redirect(url_for('ad' \
    'min_dashboard'))

@app.route('/clean-duplicates')
@admin_required
def clean_duplicates():
    with app.app_context():
        subquery = db.session.query(
            db.func.min(Item.id).label('min_id')
        ).group_by(
            Item.title, Item.user_id, Item.created_at
        ).subquery()
        Item.query.filter(
            ~Item.id.in_(db.session.query(subquery.c.min_id))
        ).delete(synchronize_session=False)
        db.session.commit()
    flash('重复数据清理完成', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/init-db')
def init_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@test.com').first():
            admin = User(username='admin', email='admin@test.com', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    return '数据库初始化成功（默认管理员：admin@test.com，密码：admin123）'

# 获取当前登录用户（导航栏显示昵称）
@app.context_processor
def inject_current_user():
    current_user = None
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
    return {'current_user': current_user}

if __name__ == '__main__':
    app.run(debug=True)