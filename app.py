import os
import random
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KoDawn-Secret-Key-Change-This'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kodawn.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- 数据库模型 ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20))
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    
    # 【新增】自定义称谓
    dispatcher_label = db.Column(db.String(50), default="放号员") # 例如：医生、讲师
    booker_label = db.Column(db.String(50), default="取号员")     # 例如：患者、学生

    # 字段配置
    dispatcher_fields = db.Column(db.String(500), default="诊室,详情")
    booker_fields = db.Column(db.String(500), default="姓名,电话")
    dispatcher_visible_fields = db.Column(db.String(500), default="姓名") 
    
    allow_edit = db.Column(db.Boolean, default=True)
    activities = db.relationship('Activity', backref='project', cascade="all, delete-orphan")
    dispatchers = db.relationship('User', backref='project', cascade="all, delete-orphan")

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    end_date = db.Column(db.Date, nullable=True)
    slots = db.relationship('Slot', backref='activity', cascade="all, delete-orphan")

class Slot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'), nullable=False)
    dispatcher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dispatcher = db.relationship('User', backref='slots')
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    capacity = db.Column(db.Integer, default=1)
    current_count = db.Column(db.Integer, default=0)
    info_json = db.Column(db.Text)
    bookings = db.relationship('Booking', backref='slot', cascade="all, delete-orphan")

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slot_id = db.Column(db.Integer, db.ForeignKey('slot.id'), nullable=False)
    booker_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

# --- 辅助函数 ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_code(length):
    while True:
        range_start = 10**(length-1)
        range_end = (10**length) - 1
        code = str(random.randint(range_start, range_end))
        if length == 6:
            if not Project.query.filter_by(code=code).first(): return code
        elif length == 8:
            if not Activity.query.filter_by(code=code).first(): return code

# --- 命令行指令 ---

@app.cli.command("create-admin")
def create_admin():
    username = input("请输入管理员用户名: ")
    password = input("请输入管理员密码: ")
    if User.query.filter_by(username=username).first():
        print("错误：该用户名已存在。")
        return
    user = User(username=username, role='admin')
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    print(f"管理员 {username} 创建成功！")

# --- 通用路由 ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin_dash') if user.role == 'admin' else url_for('dispatcher_dash'))
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_pass = request.form.get('password')
        if new_pass:
            current_user.set_password(new_pass)
            db.session.commit()
            flash('密码已修改')
            return redirect(url_for('logout'))
    return render_template('login.html', is_profile=True)

# --- 管理员功能 ---

@app.route('/admin')
@login_required
def admin_dash():
    if current_user.role != 'admin': abort(403)
    projects = Project.query.all()
    return render_template('admin_dash.html', projects=projects)

@app.route('/admin/create_project', methods=['POST'])
@login_required
def create_project():
    if current_user.role != 'admin': abort(403)
    name = request.form.get('name')
    if name:
        code = generate_code(6)
        p = Project(name=name, code=code)
        db.session.add(p)
        db.session.commit()
        flash(f'项目创建成功，编号：{code}')
    return redirect(url_for('admin_dash'))

@app.route('/admin/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def project_edit(project_id):
    if current_user.role != 'admin': abort(403)
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_config':
            # 保存自定义称谓
            project.dispatcher_label = request.form.get('dispatcher_label', '放号员')
            project.booker_label = request.form.get('booker_label', '取号员')
            
            project.dispatcher_fields = request.form.get('dispatcher_fields')
            project.booker_fields = request.form.get('booker_fields')
            project.dispatcher_visible_fields = request.form.get('dispatcher_visible_fields')
            project.allow_edit = True if request.form.get('allow_edit') else False
            db.session.commit()
            flash('设置已保存')
        
        elif action == 'create_dispatcher':
            uname = request.form.get('username')
            pwd = request.form.get('password')
            if User.query.filter_by(username=uname).first():
                flash('用户名已存在')
            else:
                u = User(username=uname, role='dispatcher', project_id=project.id)
                u.set_password(pwd)
                db.session.add(u)
                db.session.commit()
                flash(f'{project.dispatcher_label}添加成功')
        
        elif action == 'create_activity':
            aname = request.form.get('name')
            days = int(request.form.get('days', 7))
            acode = generate_code(8)
            from datetime import timedelta
            end_date = datetime.now() + timedelta(days=days)
            act = Activity(name=aname, code=acode, project_id=project.id, end_date=end_date)
            db.session.add(act)
            db.session.commit()
            flash(f'活动创建成功，编号：{acode}')

        elif action == 'delete_project':
            db.session.delete(project)
            db.session.commit()
            flash('项目已删除')
            return redirect(url_for('admin_dash'))

    return render_template('project_edit.html', project=project)

@app.route('/admin/delete_activity/<int:activity_id>')
@login_required
def delete_activity(activity_id):
    if current_user.role != 'admin': abort(403)
    act = Activity.query.get_or_404(activity_id)
    pid = act.project_id
    db.session.delete(act)
    db.session.commit()
    flash('活动已删除')
    return redirect(url_for('project_edit', project_id=pid))

@app.route('/admin/activity/<int:activity_id>')
@login_required
def admin_activity_detail(activity_id):
    if current_user.role != 'admin': abort(403)
    activity = Activity.query.get_or_404(activity_id)
    slots = Slot.query.filter_by(activity_id=activity.id).order_by(Slot.start_time).all()
    
    for s in slots:
        s.data = json.loads(s.info_json) if s.info_json else {}
        for b in s.bookings:
            b.data = json.loads(b.booker_json) if b.booker_json else {}
            
    return render_template('admin_activity_detail.html', activity=activity, slots=slots)

# --- 放号员功能 ---

@app.route('/dispatcher')
@login_required
def dispatcher_dash():
    if current_user.role != 'dispatcher': abort(403)
    project = Project.query.get(current_user.project_id)
    return render_template('dispatcher_dash.html', project=project)

@app.route('/dispatcher/manage/<int:activity_id>', methods=['GET', 'POST'])
@login_required
def slot_manage(activity_id):
    if current_user.role != 'dispatcher': abort(403)
    activity = Activity.query.get_or_404(activity_id)
    if activity.project_id != current_user.project_id: abort(403)

    if request.method == 'POST':
        start = request.form.get('start_time')
        end = request.form.get('end_time')
        capacity = int(request.form.get('capacity'))
        
        fields = activity.project.dispatcher_fields.split(',')
        data = {}
        for f in fields:
            if f.strip():
                data[f.strip()] = request.form.get(f'field_{f.strip()}')
        
        slot = Slot(
            activity_id=activity.id,
            dispatcher_id=current_user.id,
            start_time=datetime.strptime(start, '%Y-%m-%dT%H:%M'),
            end_time=datetime.strptime(end, '%Y-%m-%dT%H:%M'),
            capacity=capacity,
            info_json=json.dumps(data)
        )
        db.session.add(slot)
        db.session.commit()
        flash('发布成功')

    my_slots = Slot.query.filter_by(activity_id=activity.id, dispatcher_id=current_user.id).order_by(Slot.start_time).all()
    
    visible_keys = [k.strip() for k in activity.project.dispatcher_visible_fields.split(',') if k.strip()]
    
    for s in my_slots:
        s.data = json.loads(s.info_json) if s.info_json else {}
        s.booking_list_processed = []
        for b in s.bookings:
            raw_data = json.loads(b.booker_json) if b.booker_json else {}
            filtered_data = {k: v for k, v in raw_data.items() if k in visible_keys}
            s.booking_list_processed.append(filtered_data)

    fields = [f.strip() for f in activity.project.dispatcher_fields.split(',') if f.strip()]
    return render_template('slot_manage.html', activity=activity, slots=my_slots, fields=fields)

@app.route('/dispatcher/delete_slot/<int:slot_id>')
@login_required
def delete_slot(slot_id):
    slot = Slot.query.get_or_404(slot_id)
    if current_user.role != 'dispatcher' or slot.dispatcher_id != current_user.id:
        abort(403)
    if not slot.activity.project.allow_edit:
        flash('管理员已锁定修改权限')
        return redirect(url_for('slot_manage', activity_id=slot.activity_id))
        
    db.session.delete(slot)
    db.session.commit()
    flash('时段已删除')
    return redirect(url_for('slot_manage', activity_id=slot.activity_id))

# --- 取号员功能 ---

@app.route('/book_entry', methods=['POST'])
def book_entry():
    code = request.form.get('code')
    act = Activity.query.filter_by(code=code).first()
    if not act:
        flash('无效的活动编号')
        return redirect(url_for('index'))
    return redirect(url_for('booking_list', code_str=code))

@app.route('/book/<code_str>')
def booking_list(code_str):
    act = Activity.query.filter_by(code=code_str).first_or_404()
    if act.end_date and act.end_date < datetime.now().date():
        flash('该活动已结束')
        return redirect(url_for('index'))
        
    slots = Slot.query.filter_by(activity_id=act.id).order_by(Slot.start_time).all()
    valid_slots = []
    for s in slots:
        s.data = json.loads(s.info_json) if s.info_json else {}
        s.remain = s.capacity - s.current_count
        valid_slots.append(s)
        
    return render_template('booking_list.html', activity=act, slots=valid_slots)

@app.route('/book/<code_str>/slot/<int:slot_id>', methods=['GET', 'POST'])
def booking_form(code_str, slot_id):
    slot = Slot.query.get_or_404(slot_id)
    act = slot.activity
    
    if slot.current_count >= slot.capacity:
        flash('该时段已约满')
        return redirect(url_for('booking_list', code_str=code_str))

    fields = [f.strip() for f in act.project.booker_fields.split(',') if f.strip()]

    if request.method == 'POST':
        data = {}
        for f in fields:
            data[f] = request.form.get(f'field_{f}')
        
        booking = Booking(slot_id=slot.id, booker_json=json.dumps(data))
        slot.current_count += 1
        db.session.add(booking)
        db.session.commit()
        return render_template('success.html', code=code_str)

    slot_info = json.loads(slot.info_json) if slot.info_json else {}
    return render_template('booking_form.html', slot=slot, slot_info=slot_info, fields=fields, activity=act)

# --- 初始化 ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)