import os
import random
import json
import click # 用于命令行参数
from datetime import datetime, timedelta
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
    role = db.Column(db.String(20)) # 'admin' 或 'dispatcher'
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    dispatcher_label = db.Column(db.String(50), default="放号员")
    booker_label = db.Column(db.String(50), default="取号员")
    dispatcher_fields = db.Column(db.String(500), default="诊室,详情")
    booker_fields = db.Column(db.String(500), default="姓名,电话")
    dispatcher_visible_fields = db.Column(db.String(500), default="姓名") 
    time_mode = db.Column(db.String(20), default="manual") 
    allowed_weekdays = db.Column(db.String(50), default="0,1,2,3,4,5,6")
    class_sections_json = db.Column(db.Text, default="")
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

def get_default_sections():
    return [
        {"name": "第一节", "start": "08:00", "end": "09:30"},
        {"name": "第二节", "start": "10:00", "end": "11:30"},
        {"name": "第三节", "start": "13:30", "end": "15:00"},
        {"name": "第四节", "start": "15:20", "end": "16:50"},
        {"name": "第五节", "start": "17:10", "end": "18:40"},
        {"name": "第六节", "start": "19:30", "end": "21:00"}
    ]

# --- 命令行指令 (新增用户管理功能) ---

@app.cli.command("create-admin")
def create_admin():
    """创建项目管理员账号"""
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

@app.cli.command("list-users")
def list_users():
    """【新】查看所有用户列表"""
    users = User.query.all()
    print("-" * 60)
    print(f"{'ID':<5} | {'用户名':<20} | {'角色':<10} | {'项目ID'}")
    print("-" * 60)
    for u in users:
        role_name = "项目管理员" if u.role == 'admin' else "放号员"
        pid = u.project_id if u.project_id else "N/A"
        print(f"{u.id:<5} | {u.username:<20} | {role_name:<10} | {pid}")
    print("-" * 60)

@app.cli.command("edit-user")
def edit_user():
    """【新】修改指定用户的账号或密码"""
    list_users() # 先展示列表方便查看ID
    print("\n--- 修改模式 ---")
    user_id = input("请输入要修改的用户 ID: ")
    if not user_id.isdigit():
        print("无效的 ID")
        return
    
    user = User.query.get(int(user_id))
    if not user:
        print("找不到该用户")
        return

    print(f"当前修改对象: {user.username} ({'管理员' if user.role=='admin' else '放号员'})")
    
    new_username = input("请输入新用户名 (直接回车表示不修改): ")
    if new_username:
        if User.query.filter_by(username=new_username).first() and new_username != user.username:
            print("错误：用户名已存在")
            return
        user.username = new_username
        print("用户名已标记更新")

    new_password = input("请输入新密码 (直接回车表示不修改): ")
    if new_password:
        user.set_password(new_password)
        print("密码已标记更新")

    if new_username or new_password:
        db.session.commit()
        print(">>> 修改成功！")
    else:
        print("未做任何修改")

# --- 路由逻辑 ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dash'))
        elif current_user.role == 'dispatcher':
            return redirect(url_for('dispatcher_dash'))
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
        # 【修改】严格的修改密码流程
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')

        # 1. 验证原密码
        if not current_user.check_password(old_pass):
            flash('原密码错误，请重试')
            return redirect(url_for('profile'))
        
        # 2. 验证两次新密码一致
        if new_pass != confirm_pass:
            flash('两次输入的新密码不一致')
            return redirect(url_for('profile'))
        
        # 3. 验证新密码不能为空
        if not new_pass:
             flash('新密码不能为空')
             return redirect(url_for('profile'))

        current_user.set_password(new_pass)
        db.session.commit()
        flash('密码修改成功，请重新登录')
        logout_user() # 强制登出让用户重登
        return redirect(url_for('login'))
        
    return render_template('login.html', is_profile=True)

# --- 管理员 ---

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
        sections = get_default_sections()
        p = Project(name=name, code=code, class_sections_json=json.dumps(sections))
        db.session.add(p)
        db.session.commit()
        flash(f'项目创建成功，编号：{code}')
    return redirect(url_for('admin_dash'))

@app.route('/admin/delete_project/<int:project_id>')
@login_required
def delete_project_direct(project_id):
    if current_user.role != 'admin': abort(403)
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    flash('项目已删除')
    return redirect(url_for('admin_dash'))

@app.route('/admin/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
def project_edit(project_id):
    if current_user.role != 'admin': abort(403)
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_config':
            project.dispatcher_label = request.form.get('dispatcher_label', '放号员')
            project.booker_label = request.form.get('booker_label', '取号员')
            project.dispatcher_fields = request.form.get('dispatcher_fields')
            project.booker_fields = request.form.get('booker_fields')
            project.dispatcher_visible_fields = request.form.get('dispatcher_visible_fields')
            project.allow_edit = True if request.form.get('allow_edit') else False
            
            project.time_mode = request.form.get('time_mode')
            weekdays = request.form.getlist('allowed_weekdays')
            project.allowed_weekdays = ",".join(weekdays)
            
            if project.time_mode == 'class':
                sec_names = request.form.getlist('sec_name[]')
                sec_starts = request.form.getlist('sec_start[]')
                sec_ends = request.form.getlist('sec_end[]')
                new_sections = []
                for i in range(len(sec_names)):
                    if sec_names[i] and sec_starts[i] and sec_ends[i]:
                        new_sections.append({
                            "name": sec_names[i],
                            "start": sec_starts[i],
                            "end": sec_ends[i]
                        })
                project.class_sections_json = json.dumps(new_sections)

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
                flash('人员添加成功')
        
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

    sections = json.loads(project.class_sections_json) if project.class_sections_json else get_default_sections()
    allowed_wd = project.allowed_weekdays.split(',') if project.allowed_weekdays else []
    
    return render_template('project_edit.html', project=project, sections=sections, allowed_wd=allowed_wd)

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

# --- 放号员 ---

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
    project = activity.project
    if project.id != current_user.project_id: abort(403)

    if request.method == 'POST':
        capacity = int(request.form.get('capacity'))
        start_dt = None
        end_dt = None
        
        if project.time_mode == 'manual':
            s_str = request.form.get('start_time')
            e_str = request.form.get('end_time')
            start_dt = datetime.strptime(s_str, '%Y-%m-%dT%H:%M')
            end_dt = datetime.strptime(e_str, '%Y-%m-%dT%H:%M')
        else:
            date_str = request.form.get('select_date')
            time_range = request.form.get('time_range')
            if not date_str or not time_range:
                flash('请完整选择日期和时段')
                return redirect(url_for('slot_manage', activity_id=activity.id))

            selected_date = datetime.strptime(date_str, '%Y-%m-%d')
            weekday_str = str(selected_date.weekday())
            allowed_list = project.allowed_weekdays.split(',')
            if weekday_str not in allowed_list:
                flash('所选日期的星期不在允许放号范围内')
                return redirect(url_for('slot_manage', activity_id=activity.id))
            
            t_start_str, t_end_str = time_range.split('|')
            start_dt = datetime.strptime(f"{date_str} {t_start_str}", '%Y-%m-%d %H:%M')
            end_dt = datetime.strptime(f"{date_str} {t_end_str}", '%Y-%m-%d %H:%M')

        fields = project.dispatcher_fields.split(',')
        data = {}
        for f in fields:
            if f.strip():
                data[f.strip()] = request.form.get(f'field_{f.strip()}')
        
        slot = Slot(
            activity_id=activity.id,
            dispatcher_id=current_user.id,
            start_time=start_dt,
            end_time=end_dt,
            capacity=capacity,
            info_json=json.dumps(data)
        )
        db.session.add(slot)
        db.session.commit()
        flash('发布成功')
        return redirect(url_for('slot_manage', activity_id=activity.id))

    my_slots = Slot.query.filter_by(activity_id=activity.id, dispatcher_id=current_user.id).order_by(Slot.start_time).all()
    visible_keys = [k.strip() for k in project.dispatcher_visible_fields.split(',') if k.strip()]
    
    for s in my_slots:
        s.data = json.loads(s.info_json) if s.info_json else {}
        s.booking_list_processed = []
        for b in s.bookings:
            raw_data = json.loads(b.booker_json) if b.booker_json else {}
            filtered_data = {k: v for k, v in raw_data.items() if k in visible_keys}
            s.booking_list_processed.append(filtered_data)

    fields = [f.strip() for f in project.dispatcher_fields.split(',') if f.strip()]
    
    time_options = []
    if project.time_mode == 'class':
        sections = json.loads(project.class_sections_json) if project.class_sections_json else []
        for s in sections:
            time_options.append({
                'label': f"{s['name']} ({s['start']} - {s['end']})",
                'value': f"{s['start']}|{s['end']}"
            })
    elif project.time_mode == 'hourly':
        for h in range(24):
            s = f"{h:02d}:00"
            e = f"{h+1:02d}:00"
            time_options.append({
                'label': f"{s} - {e}",
                'value': f"{s}|{e}"
            })

    return render_template('slot_manage.html', activity=activity, slots=my_slots, fields=fields, time_options=time_options)

@app.route('/dispatcher/delete_slot/<int:slot_id>')
@login_required
def delete_slot(slot_id):
    slot = Slot.query.get_or_404(slot_id)
    if current_user.role != 'dispatcher' or slot.dispatcher_id != current_user.id: abort(403)
    if not slot.activity.project.allow_edit:
        flash('管理员已锁定修改权限')
        return redirect(url_for('slot_manage', activity_id=slot.activity_id))
    db.session.delete(slot)
    db.session.commit()
    flash('时段已删除')
    return redirect(url_for('slot_manage', activity_id=slot.activity_id))

# --- 取号员 ---

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