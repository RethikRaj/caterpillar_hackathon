from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv
from deep_translator import GoogleTranslator
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config["MONGO_URI"] = os.getenv("MONGO_URI")

if not app.config["MONGO_URI"]:
    raise ValueError("MONGO_URI not set or .env file not found!")

mongo = PyMongo(app)
users_col = mongo.db.users
tasks_col = mongo.db.tasks
logs_col  = mongo.db.logs
forum_col = mongo.db.forum_posts

# Ensure default admin exists
if not users_col.find_one({'username': 'admin'}):
    users_col.insert_one({
        'username': 'admin',
        'password': generate_password_hash('adminpass'),
        'role': 'admin'
    })

# Decorator to restrict access
from functools import wraps

def login_required(role=None):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.context_processor
def inject_user():
    return dict(current_user=session.get('user'), current_role=session.get('role'))

@app.template_filter('datetimeformat')
def datetimeformat(value):
    from datetime import datetime
    return datetime.fromtimestamp(int(value) / 1000).strftime('%Y-%m-%d %H:%M:%S')

@app.route('/change_password', methods=['GET','POST'])
@login_required()
def change_password():
    if request.method == 'POST':
        old = request.form['old_password']
        new = request.form['new_password']
        user = users_col.find_one({'username': session['user']})
        if not check_password_hash(user['password'], old):
            flash('Old password incorrect','danger')
        else:
            users_col.update_one(
                {'username': session['user']},
                {'$set': {'password': generate_password_hash(new)}}
            )
            flash('Password updated','success')
            return redirect(url_for('login') if session['role']=='operator' else url_for('admin_login'))
    return render_template('change_password.html')

@app.route('/admin_login', methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        uname = request.form['username']
        pwd   = request.form['password']
        user = users_col.find_one({'username': uname, 'role': 'admin'})
        if user and check_password_hash(user['password'], pwd):
            session.clear()
            session['user'] = uname
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials','danger')
    return render_template('admin_login.html')

@app.route('/admin_dashboard', methods=['GET','POST'])
@login_required(role='admin')
def admin_dashboard():
    if request.method=='POST':
        if 'create_op' in request.form:
            op = request.form['new_op'].strip()
            pw = request.form['new_pw']
            if users_col.find_one({'username': op}):
                flash('Operator already exists','warning')
            else:
                users_col.insert_one({
                    'username': op,
                    'password': generate_password_hash(pw),
                    'role': 'operator'
                })
                flash('Operator created','success')

        if 'alloc_submit' in request.form:
            op    = request.form['op_select']
            role  = request.form['role_select']
            date  = request.form['date']
            raw   = request.form['tasks_raw'].splitlines()
            tasks = [{"task": t.strip(), "done": False} for t in raw if t.strip()]
            tasks_col.update_one(
                {'operator': op, 'role': role, 'date': date},
                {'$set': {'tasks': tasks}},
                upsert=True
            )
            flash('Tasks allocated','success')

    users = list(users_col.find({'role':'operator'}, {'password':0}))
    tasks = list(tasks_col.find({}, {'_id':0}))
    logs  = list(logs_col.find({}, {'_id':0}))
    return render_template('admin_dashboard.html', users=users, tasks=tasks, logs=logs)

@app.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/', methods=['GET','POST'])
def login():
    if request.method=='POST':
        op = request.form['operator'].strip()
        pw = request.form['password']
        user = users_col.find_one({'username': op, 'role': 'operator'})
        if user and check_password_hash(user['password'], pw):
            session.clear()
            session['user'] = op
            session['role'] = 'operator'
            return redirect(url_for('select_role'))
        flash('Invalid credentials','danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/role_select', methods=['GET','POST'])
@login_required(role='operator')
def select_role():
    if request.method=='POST':
        session['role_sel'] = request.form['role']
        session['machine']  = request.form['machine']
        return redirect(url_for('task_dashboard'))
    return render_template('role_select.html')

@app.route('/dashboard', methods=['GET','POST'])
@login_required(role='operator')
def task_dashboard():
    op   = session['user']
    role = session['role_sel']
    date = datetime.today().strftime('%Y-%m-%d')

    doc  = tasks_col.find_one({'operator':op,'role':role,'date':date})
    tlist = doc['tasks'] if doc else []

    if request.method=='POST':
        updated_tasks = []
        for i, task in enumerate(tlist):
            if f'done_{i}' in request.form:
                task['done'] = not task['done']
            if f'del_{i}' in request.form:
                continue  # Skip task to delete
            updated_tasks.append(task)

        tasks_col.update_one(
            {'operator': op, 'role': role, 'date': date},
            {'$set': {'tasks': updated_tasks}}
        )
        return redirect(url_for('task_dashboard'))

    return render_template('task_dashboard.html',
                           tasks=tlist, op=op,
                           role=role, machine=session['machine'],
                           date=date)

@app.route('/performance')
@login_required(role='operator')
def performance():
    op   = session['user']
    logs = list(logs_col.find({'operator':op}, {'_id':0}))
    dates     = [l['date'] for l in logs]
    idle_vals = [l.get('idle_time',0) for l in logs]
    fuel_vals = [l.get('fuel',0) for l in logs]
    return render_template('performance.html',
                           dates=dates, idle_times=idle_vals, fuel_used=fuel_vals)

@app.route('/forum')
@login_required(role='operator')
def forum():
    posts = list(forum_col.find({}, {'_id': 0}))
    posts.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    return render_template('forum.html', posts=posts, username=session['user'])

@app.route('/add_post', methods=['POST'])
@login_required(role='operator')
def add_post():
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    timestamp = int(datetime.utcnow().timestamp() * 1000)
    forum_col.insert_one({
        'title': title,
        'content': content,
        'author': session['user'],
        'timestamp': timestamp
    })
    return jsonify({'message': 'Post added'})

@app.route('/translate', methods=['POST'])
@login_required(role='operator')
def translate():
    data = request.get_json()
    text = data.get('text')
    target = data.get('target_lang')
    try:
        translated = GoogleTranslator(source='auto', target=target).translate(text)
        return jsonify({'translatedContent': translated})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
