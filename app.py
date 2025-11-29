import os
import random
import json
import string
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text # 用于执行原生SQL升级数据库

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
    dispatcher_configs = db.relationship('DispatcherConfig', backref='activity', cascade="all, delete-orphan")

class DispatcherConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'), nullable=False)
    dispatcher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    enable_limit = db.Column(db.Boolean, default=False)
    max_quota = db.Column(db.Integer, default=0)

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
    booking_code = db.Column(db.String(10), unique=True, nullable=True) # 升级时允许为空，之后填补
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
        elif length == 10:
            if not Booking.query.filter_by(booking_code=code).first(): return code

def get_default_sections():
    return [
        {"name": "第一节", "start": "08:00", "end": "09:30"},
        {"name": "第二节", "start": "10:00", "end": "11:30"},
        {"name": "第三节", "start": "13:30", "end": "15:00"},
        {"name": "第四节", "start": "15:20", "end": "16:50"},
        {"name": "第五节", "start": "17:10", "end": "18:40"},
        {"name": "第六节", "start": "19:30", "end": "21:00"}
    ]

# --- 核心：数据库无损升级指令 ---

@app.cli.command("update-db")
def update_db_schema():
    """【重要】升级数据库结构，保留旧数据"""
    print("开始检查数据库结构...")
    
    # 1. 尝试创建所有新定义的表（如果表不存在，会自动创建；如果存在，会跳过）
    db.create_all()
    print("√ 基础表结构检查完成")

    # 2. 补全新增的字段 (SQLite 不支持直接检查字段是否存在，所以我们尝试添加，失败则忽略)
    # 格式: (表名, 字段名, 类型, 默认值)
    migrations = [
        ('activity', 'end_date', 'DATE', 'NULL'),
        ('booking', 'booking_code', 'VARCHAR(10)', 'NULL'),
        ('project', 'time_mode', 'VARCHAR(20)', "'manual'"),
        ('project', 'class_sections_json', 'TEXT', "''"),
        ('project', 'allowed_weekdays', 'VARCHAR(50)', "'0,1,2,3,4,5,6'"),
        ('project', 'dispatcher_label', 'VARCHAR(50)', "'放号员'"),
        ('project', 'booker_label', 'VARCHAR(50)', "'取号员'"),
    ]

    with db.engine.connect() as conn:
        for table, col, col_type, default in migrations:
            try:
                # 尝试添加列
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type} DEFAULT {default}"))
                print(f"  + 已向 {table} 表添加新字段: {col}")
            except Exception as e:
                # 如果报错，说明字段可能已经存在，或者表不存在，我们忽略错误
                pass
        conn.commit()

    # 3. 数据回填：为旧的预约记录生成取号码
    print("检查旧数据完整性...")
    bookings_without_code = Booking.query.filter(Booking.booking_code == None).all()
    if bookings_without_code:
        print(f"  > 发现 {len(bookings_without_code)} 个旧预约缺失取号码，正在生成...")
        count = 0
        for b in bookings_without_code:
            b.booking_code = generate_code(10)
            count += 1
        db.session.commit()
        print(f"  √ 已修复 {count} 条数据")
    
    print("\n恭喜！数据库升级完成，你可以正常启动网站了。")


# --- 其他命令行指令 ---

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

@app.cli.command("list-users")
def list_users():
    users = User.query.all()
    print(f"{'ID':<5} | {'用户名':<20} | {'角色':<10} | {'项目ID'}")
    for u in users:
        role_name = "项目管理员" if u.role == 'admin' else "放号员"
        pid = u.project_id if u.project_id else "N/A"
        print(f"{u.id:<5} | {u.username:<20} | {role_name:<10} | {pid}")

@app.cli.command("edit-user")
def edit_user():
    list_users()
    user_id = input("请输入要修改的用户 ID: ")
    if not user_id.isdigit(): return
    user = User.query.get(int(user_id))
    if not user: return
    new_username = input("新用户名 (回车跳过): ")
    if new_username: user.username = new_username
    new_password = input("新密码 (回车跳过): ")
    if new_password: user.set_password(new_password)
    db.session.commit()
    print("修改成功")

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
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')

        if not current_user.check_password(old_pass):
            flash('原密码错误')
            return redirect(url_for('profile'))
        if new_pass != confirm_pass:
            flash('两次新密码不一致')
            return redirect(url_for('profile'))
        if not new_pass:
             flash('新密码不能为空')
             return redirect(url_for('profile'))

        current_user.set_password(new_pass)
        db.session.commit()
        flash('密码修改成功，请重新登录')
        logout_user()
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
                        new_sections.append({"name": sec_names[i], "start": sec_starts[i], "end": sec_ends[i]})
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
            acode = generate_code(8)
            end_date_str = request.form.get('end_date')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else None
            
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

@app.route('/admin/delete_dispatcher/<int:dispatcher_id>')
@login_required
def delete_dispatcher(dispatcher_id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(dispatcher_id)
    if user.role != 'dispatcher':
        flash('只能删除放号员')
        return redirect(url_for('admin_dash'))
    
    pid = user.project_id
    db.session.delete(user)
    db.session.commit()
    flash('放号员已删除')
    return redirect(url_for('project_edit', project_id=pid))

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

    config = DispatcherConfig.query.filter_by(activity_id=activity.id, dispatcher_id=current_user.id).first()
    if not config:
        config = DispatcherConfig(activity_id=activity.id, dispatcher_id=current_user.id)
        db.session.add(config)
        db.session.commit()

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_limit':
            config.enable_limit = True if request.form.get('enable_limit') else False
            config.max_quota = int(request.form.get('max_quota', 0))
            db.session.commit()
            flash('限额配置已更新')
            return redirect(url_for('slot_manage', activity_id=activity.id))
        
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
            if activity.end_date and selected_date.date() > activity.end_date:
                flash(f'不能设置截止日期({activity.end_date})之后的时间')
                return redirect(url_for('slot_manage', activity_id=activity.id))

            weekday_str = str(selected_date.weekday())
            if weekday_str not in project.allowed_weekdays.split(','):
                flash('所选日期的星期不在允许放号范围内')
                return redirect(url_for('slot_manage', activity_id=activity.id))
            
            t_start_str, t_end_str = time_range.split('|')
            start_dt = datetime.strptime(f"{date_str} {t_start_str}", '%Y-%m-%d %H:%M')
            end_dt = datetime.strptime(f"{date_str} {t_end_str}", '%Y-%m-%d %H:%M')

        if project.time_mode == 'manual':
             if activity.end_date and start_dt.date() > activity.end_date:
                flash(f'不能设置截止日期({activity.end_date})之后的时间')
                return redirect(url_for('slot_manage', activity_id=activity.id))

        fields = project.dispatcher_fields.split(',')
        data = {}
        for f in fields:
            if f.strip(): data[f.strip()] = request.form.get(f'field_{f.strip()}')
        
        slot = Slot(
            activity_id=activity.id, dispatcher_id=current_user.id,
            start_time=start_dt, end_time=end_dt, capacity=capacity,
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
            time_options.append({'label': f"{s['name']} ({s['start']} - {s['end']})", 'value': f"{s['start']}|{s['end']}"})
    elif project.time_mode == 'hourly':
        for h in range(24):
            s = f"{h:02d}:00"
            e = f"{h+1:02d}:00"
            time_options.append({'label': f"{s} - {e}", 'value': f"{s}|{e}"})

    return render_template('slot_manage.html', activity=activity, slots=my_slots, fields=fields, time_options=time_options, config=config)

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
    
    dispatcher_status = {}
    involved_dispatchers = set([s.dispatcher_id for s in slots])
    
    for did in involved_dispatchers:
        conf = DispatcherConfig.query.filter_by(activity_id=act.id, dispatcher_id=did).first()
        total_bookings = Booking.query.join(Slot).filter(Slot.activity_id == act.id, Slot.dispatcher_id == did).count()
        is_full = False
        if conf and conf.enable_limit and total_bookings >= conf.max_quota:
            is_full = True
        dispatcher_status[did] = is_full

    valid_slots = []
    for s in slots:
        s.data = json.loads(s.info_json) if s.info_json else {}
        s.remain = s.capacity - s.current_count
        s.dispatcher_full = dispatcher_status.get(s.dispatcher_id, False)
        valid_slots.append(s)
        
    return render_template('booking_list.html', activity=act, slots=valid_slots)

@app.route('/book/<code_str>/slot/<int:slot_id>', methods=['GET', 'POST'])
def booking_form(code_str, slot_id):
    slot = Slot.query.get_or_404(slot_id)
    act = slot.activity
    
    if slot.current_count >= slot.capacity:
        flash('该时段已约满')
        return redirect(url_for('booking_list', code_str=code_str))
    
    conf = DispatcherConfig.query.filter_by(activity_id=act.id, dispatcher_id=slot.dispatcher_id).first()
    if conf and conf.enable_limit:
        total_bookings = Booking.query.join(Slot).filter(Slot.activity_id == act.id, Slot.dispatcher_id == slot.dispatcher_id).count()
        if total_bookings >= conf.max_quota:
             flash('该放号员接单已达上限，无法预约')
             return redirect(url_for('booking_list', code_str=code_str))

    fields = [f.strip() for f in act.project.booker_fields.split(',') if f.strip()]

    if request.method == 'POST':
        data = {}
        for f in fields:
            data[f] = request.form.get(f'field_{f}')
            
        b_code = generate_code(10)
        
        booking = Booking(
            slot_id=slot.id, 
            booker_json=json.dumps(data),
            booking_code=b_code
        )
        slot.current_count += 1
        db.session.add(booking)
        db.session.commit()
        return render_template('success.html', code=code_str, booking_code=b_code)

    slot_info = json.loads(slot.info_json) if slot.info_json else {}
    return render_template('booking_form.html', slot=slot, slot_info=slot_info, fields=fields, activity=act)

# --- 编辑/管理取号 ---

@app.route('/manage_booking_entry', methods=['GET', 'POST'])
def manage_booking_entry():
    if request.method == 'POST':
        b_code = request.form.get('booking_code')
        booking = Booking.query.filter_by(booking_code=b_code).first()
        if booking:
            return redirect(url_for('manage_booking_view', b_code=b_code))
        else:
            flash('未找到该取号码')
    return render_template('manage_booking_entry.html')

@app.route('/manage_booking/view/<b_code>')
def manage_booking_view(b_code):
    booking = Booking.query.filter_by(booking_code=b_code).first_or_404()
    booking.data = json.loads(booking.booker_json)
    booking.slot.data = json.loads(booking.slot.info_json) if booking.slot.info_json else {}
    return render_template('manage_booking_view.html', booking=booking)

@app.route('/manage_booking/delete/<b_code>', methods=['POST'])
def manage_booking_delete(b_code):
    booking = Booking.query.filter_by(booking_code=b_code).first_or_404()
    slot = booking.slot
    slot.current_count -= 1
    if slot.current_count < 0: slot.current_count = 0
    db.session.delete(booking)
    db.session.commit()
    flash('取号已删除（取消预约）')
    return redirect(url_for('index'))

# --- 初始化 ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)