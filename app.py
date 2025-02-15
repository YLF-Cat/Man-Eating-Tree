from flask import Flask, render_template, redirect, url_for, request, flash,current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bootstrap import Bootstrap
from datetime import datetime
import random
import string  
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 数据库模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))
    nickname = db.Column(db.String(80))
    is_admin = db.Column(db.Boolean, default=False)
    score = db.Column(db.Float, default=0)
    ip_address = db.Column(db.String(120))
    reg_key = db.Column(db.String(80))
    key = db.Column(db.String(10), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    showscore = db.Column(db.Boolean, default=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    options = db.Column(db.String(255))  # 逗号分隔的选项
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    choice = db.Column(db.String(1))
    timestamp = db.Column(db.DateTime, default=datetime.now)
    score_change = db.Column(db.Integer, default=0)
    user = db.relationship('User', backref='answers')  # 添加外键关系
class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(10), unique=True, nullable=False)
    status = db.Column(db.String(10), default='未使用')

class RegKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False)
    initial_score = db.Column(db.Integer, default=0)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# 初始化管理员账号
def create_admin():
    admin = User.query.filter_by(username='Admin').first()
    if not admin:
        admin = User(
            username='Admin',
            password='yuanshenstart',
            nickname='Admin',
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# Flask-Login配置
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 路由部分
@app.route('/')
@login_required
def index():
    question = Question.query.filter_by(is_active=True).first()
    users = User.query.all()  # 获取所有用户
    user_data = [(user.id, user.nickname, user.score) for user in users]
    ushowscore = User.query.filter_by(id=1).first()
    showscore = ushowscore.showscore
    return render_template('question.html', question=question,users=user_data,showscore=showscore)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password == request.form['password']:
            login_user(user)
            return redirect(url_for('index'))
        flash('无效的用户名或密码')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        nickname = request.form.get('nickname')
        key = request.form.get('key')

        # 检查密钥是否有效
        valid_key = Key.query.filter_by(key=key, status='未使用').first()
        if not valid_key:
            flash('无效的密钥')
            return redirect(url_for('register'))

        # 创建新用户
        ip_address = request.remote_addr
        new_user = User(username=username, password=password, nickname=nickname, key=key, ip_address=ip_address)
        db.session.add(new_user)
        valid_key.status = '已使用'
        db.session.commit()
        flash('注册成功！')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    # 获取最近一次测试的题目
    question = Question.query.order_by(Question.created_at.desc()).first()
    options = question.options.split(',') if question else []
    keys = Key.query.all()
    users = User.query.all()
    return render_template('admin.html', options=options, keys=keys, users=users, question=question)

@app.route('/adjust_scores', methods=['POST'])
@login_required
def adjust_scores():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    action_type = request.form.get('action_type', '')
    if action_type == 'A':
        option = request.form.get('option', '')
        change = float(request.form.get('change', 0))
        answers = Answer.query.filter_by(choice=option).all()
        for a in answers:
            a.user.score += change
            a.score_change += change
    elif action_type == 'B':
        user_id = int(request.form.get('user_id', 0))
        change = float(request.form.get('change', 0))
        a = Answer.query.filter_by(user_id=user_id).first()
        user = User.query.get(user_id)
        if user:
            user.score += change
            a.score_change += change
    elif action_type == 'C':
        option = request.form.get('option', '')
        prob = float(request.form.get('prob', 0)) / 100
        change1 = float(request.form.get('change1', 0))
        change2 = float(request.form.get('change2', 0))
        answers = Answer.query.filter_by(choice=option).all()
        for a in answers:
            if random.random() < prob:
                a.user.score += change1
                a.score_change += change1
            else:
                a.user.score += change2
                a.score_change += change2
    elif action_type == 'stop':
        question_id = int(request.form.get('question_id', 0))
        question = Question.query.get(question_id)
        if question:
            question.is_active = False
            db.session.commit()
            flash('停止收集成功！')
    db.session.commit()
    return redirect(url_for('admin_panel'))


@app.route('/submit_answer', methods=['POST'])
@login_required
def submit_answer():
    question = Question.query.filter_by(is_active=True).first()
    if not question or not question.is_active:
        flash('当前没有正在进行的题目')
        return redirect(url_for('index'))
    choice = request.form.get('choice', '').upper()
    if choice not in question.options.split(','):
        flash('无效的选项')
        return redirect(url_for('index'))
    existing = Answer.query.filter_by(
        user_id=current_user.id,
        question_id=question.id
    ).first()
    if existing:
        existing.choice = choice
        existing.timestamp = datetime.utcnow()
    else:
        answer = Answer(
            user_id=current_user.id,
            question_id=question.id,
            choice=choice
        )
        db.session.add(answer)
    db.session.commit()
    flash('提交成功！')
    return redirect(url_for('index'))


@app.route('/generate_key', methods=['POST'])
@login_required
def generate_key():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    key_count = int(request.form.get('key_count', 0))
    for _ in range(key_count):
        key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        new_key = Key(key=key)
        db.session.add(new_key)
    db.session.commit()
    flash('密钥生成成功！')
    return redirect(url_for('admin_panel'))


@app.route('/create_key', methods=['POST'])
@login_required
def create_key():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    key = secrets.token_hex(4).upper()
    new_key = RegKey(
        key=key,
        initial_score=int(request.form['initial_score']),
        created_by=current_user.id
    )
    db.session.add(new_key)
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin_actions', methods=['POST'])
@login_required
def admin_actions():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    action = request.form.get('admin_action', '')
    if action == 'clear_scores':
        User.query.update({User.score: 0.0})
        db.session.commit()
        flash('所有人的积分已清空')
    elif action == 'clear_accounts':
        User.query.filter(User.is_admin == False).delete()
        Answer.query.delete()
        db.session.commit()
        flash('所有人的账号已清空')
    elif action == 'clear_keys':
        Key.query.delete()
        db.session.commit()
        flash('所有密钥已清空')
    elif action == 'delete_account':
        user_id = int(request.form.get('delete_account_id', 0))
        user = User.query.get(user_id)
        if user:
            Answer.query.filter_by(user_id=user_id).delete()
            db.session.delete(user)
            db.session.commit()
            flash('指定账号已删除')
        else:
            flash('用户不存在')
    elif action == 'toggle_leaderboard':
        flash('已修改')
        showscore = User.query.filter_by(id=1).first()
        showscore.showscore = not(showscore.showscore)
    db.session.commit()
    return redirect(url_for('admin_panel'))


@app.route('/create_question', methods=['POST'])
@login_required
def create_question():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    # 获取并处理选项
    options = [line.upper().strip() for line in request.form['options'].split('\n') if line.strip()]
    unique_options = list(dict.fromkeys(options))  # 去重但保留顺序
    
    if len(unique_options) < 1:
        flash('至少需要一个有效选项')
        return redirect(url_for('admin_panel'))
    
    Question.query.update({'is_active': False})  # 停用旧题目
    
    new_question = Question(
        content=request.form['content'],
        options=','.join(unique_options),
        is_active=True
    )
    db.session.add(new_question)
    db.session.commit()
    flash('题目发布成功')
    return redirect(url_for('admin_panel'))
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/history')
@login_required
def history():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    questions = Question.query.all()
    stats = {}
    missing = {}
    
    for q in questions:
        answers = Answer.query.filter_by(question_id=q.id).all()
        users = User.query.all()
        
        # 统计选项
        option_dict = {opt: {'count':0, 'answers':[]} for opt in q.options.split(',')}
        for a in answers:
            option_dict[a.choice]['count'] += 1
            option_dict[a.choice]['answers'].append(a)
        
        # 查找未答题用户
        answered_users = {a.user_id for a in answers}
        missing_users = [u for u in users if u.id not in answered_users]
        
        stats[q.id] = option_dict
        missing[q.id] = missing_users
    
    return render_template('history.html', 
                         questions=questions,
                         answer_stats=stats,
                         missing_users=missing)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(host='0.0.0.0',debug=True,port='80')
