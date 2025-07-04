from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv
from deep_translator import GoogleTranslator
import pandas as pd
import joblib
import os
import requests
import pickle

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config["MONGO_URI"] = os.getenv("MONGO_URI")

if not app.config["MONGO_URI"]:
    raise ValueError("MONGO_URI not set or .env file not found!")

mongo = PyMongo(app)
users_col    = mongo.db.users
tasks_col    = mongo.db.tasks
logs_col     = mongo.db.logs
forum_col    = mongo.db.forum_posts

# Load ML models
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

with open("label_encoders.pkl", "rb") as f:
    label_encoders = pickle.load(f)

# Ensure default admin
if not users_col.find_one({'username': 'admin'}):
    users_col.insert_one({
        'username': 'admin',
        'password': generate_password_hash('adminpass'),
        'role': 'admin'
    })

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

def datetimeformat(value):
    return datetime.fromtimestamp(int(value)/1000).strftime('%Y-%m-%d %H:%M:%S')
app.jinja_env.filters['datetimeformat'] = datetimeformat

@app.context_processor
def inject_user():
    return dict(current_user=session.get('user'), current_role=session.get('role'))

# === AUTH ROUTES ===
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

@app.route('/admin_login', methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        uname = request.form['username']
        pwd = request.form['password']
        user = users_col.find_one({'username': uname, 'role': 'admin'})
        if user and check_password_hash(user['password'], pwd):
            session.clear()
            session['user'] = uname
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials','danger')
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

# === ADMIN DASHBOARD ===
@app.route('/admin_dashboard', methods=['GET','POST'])
@login_required(role='admin')
def admin_dashboard():
    if request.method=='POST':
        if 'create_op' in request.form:
            op = request.form['new_op'].strip()
            pw = request.form['new_pw']
            if users_col.find_one({'username': op}):
                flash('Operator exists','warning')
            else:
                users_col.insert_one({'username': op,'password': generate_password_hash(pw),'role':'operator'})
                flash('Operator created','success')
        if 'alloc_submit' in request.form:
            op   = request.form['op_select']
            role = request.form['role_select']
            date = request.form['date']
            tasks = [{"task": t.strip(), "done": False} for t in request.form['tasks_raw'].splitlines() if t.strip()]
            tasks_col.update_one({'operator':op,'role':role,'date':date},{'$set':{'tasks':tasks}},upsert=True)
            flash('Tasks assigned','success')
    users = list(users_col.find({'role':'operator'},{'password':0}))
    tasks = list(tasks_col.find({},{'_id':0}))
    logs  = list(logs_col.find({},{'_id':0}))
    return render_template('admin_dashboard.html', users=users, tasks=tasks, logs=logs)

# === OPERATOR ROUTES ===
@app.route('/select_role', methods=['GET','POST'])
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
    op = session['user']
    role = session['role_sel']
    date = datetime.today().strftime('%Y-%m-%d')
    doc = tasks_col.find_one({'operator':op,'role':role,'date':date})
    tasks = doc['tasks'] if doc else []
    if request.method=='POST':
        updated = []
        for i,task in enumerate(tasks):
            if request.form.get(f'done_{i}'):
                task['done'] = True
            if not request.form.get(f'del_{i}'):
                updated.append(task)
        tasks_col.update_one({'operator':op,'role':role,'date':date},{'$set':{'tasks':updated}})
        return redirect(url_for('task_dashboard'))
    return render_template('task_dashboard.html', tasks=tasks, op=op, role=role, machine=session['machine'], date=date)

@app.route('/performance')
@login_required(role='operator')
def performance():
    op = session['user']
    logs = list(logs_col.find({'operator':op},{'_id':0}))
    dates = [l['date'] for l in logs]
    idle  = [l.get('idle_time',0) for l in logs]
    fuel  = [l.get('fuel',0) for l in logs]
    return render_template('performance.html', dates=dates, idle_times=idle, fuel_used=fuel)

@app.route('/forum')
@login_required(role='operator')
def forum():
    posts = list(forum_col.find({},{'_id':0}))
    posts.sort(key=lambda x: x.get('timestamp',0), reverse=True)
    return render_template('forum.html', posts=posts)

@app.route('/add_post', methods=['POST'])
@login_required(role='operator')
def add_post():
    data = request.get_json()
    ts = int(datetime.utcnow().timestamp()*1000)
    forum_col.insert_one({'title':data['title'],'content':data['content'],'author':session['user'],'timestamp':ts,'likes':0})
    return jsonify({'ok':True})

@app.route('/translate', methods=['POST'])
@login_required(role='operator')
def translate():
    data = request.get_json()
    try:
        trans = GoogleTranslator(source='auto',target=data['target_lang']).translate(data['text'])
        return jsonify({'translatedContent':trans})
    except:
        return jsonify({'translatedContent':data['text']})

@app.route('/track_task/<task_name>', methods=['GET', 'POST'])
@login_required(role='operator')
def track_task(task_name):
    prediction = None
    if request.method == 'POST':
        machine = request.form['machine']
        task = request.form['task']
        soil = request.form['soil']
        distance = float(request.form['distance'])
        weight = float(request.form['weight'])
        experience = int(request.form['experience'])
        temperature = float(request.form['temperature'])
        is_rainy = int(request.form['is_rainy'])
        engine_hours = float(request.form['engine_hours'])
        fuel_consumed = float(request.form['fuel_consumed'])
        load_cycles = int(request.form['load_cycles'])
        idling_time = float(request.form['idling_time'])

        machine_enc = label_encoders['Machine_Type'].transform([machine])[0]
        task_enc = label_encoders['Task_Type'].transform([task])[0]
        soil_enc = label_encoders['Soil_Type'].transform([soil])[0]

        features = [[
            machine_enc, task_enc, soil_enc, distance, weight, experience,
            temperature, is_rainy, engine_hours, fuel_consumed, load_cycles, idling_time
        ]]

        predicted_time = model.predict(features)[0]
        prediction = f"{predicted_time:.2f} minutes"

    return render_template('track_task.html', prediction=prediction)

@app.route('/get_weather', methods=['GET'])
def get_weather():
    city = request.args.get('city')
    if not city:
        return jsonify({'error': 'City not provided'}), 400

    api_key = "4770a89d38d26ba4df1200be94fdf32e"
    url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}&units=metric"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        weather_main = data['weather'][0]['main'].lower()
        description = data['weather'][0]['description']
        temp = data['main']['temp']
        humidity = data['main']['humidity']
        is_rainy = 1 if 'rain' in weather_main or 'drizzle' in weather_main else 0

        return jsonify({
            'city': data['name'],
            'condition': weather_main,
            'description': description,
            'temperature': temp,
            'humidity': humidity,
            'is_rainy': is_rainy
        })

    except requests.exceptions.RequestException:
        return jsonify({'error': 'Failed to fetch weather data'}), 500

@app.route('/safety_check')
@login_required(role='operator')
def safety_check():
    return render_template('safety_check.html')

# ✅ NEW: Real-Time Safety Prediction Page
@app.route('/real_time_safety', methods=['GET', 'POST'])
@login_required(role='operator')
def real_time_safety():
    prediction = None
    if request.method == "POST":
        data = {
            'proximity_distance': float(request.form['proximity_distance']),
            'tilt_angle': float(request.form['tilt_angle']),
            'engine_temp': float(request.form['engine_temp']),
            'idling_time': float(request.form['idling_time']),
            'machine_speed': float(request.form['machine_speed']),
            'load_percent': float(request.form['load_percent']),
            'rain_detected': int(request.form['rain_detected'])
        }
        input_df = pd.DataFrame([data])

        clf = joblib.load("incident_model_single.pkl")
        le = joblib.load("label_encoder_single.pkl")
        pred = clf.predict(input_df)
        prediction = le.inverse_transform(pred)[0]

    return render_template("real_time_safety.html", prediction=prediction)

if __name__ == '__main__':
    app.run(debug=True)
