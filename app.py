import os
import json
import sqlite3
from datetime import datetime

from flask import Flask, request, redirect, url_for, session, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me')


def init_db():
    conn = sqlite3.connect('lms.db')
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        speechace_user_id TEXT UNIQUE NOT NULL,
        test_taken INTEGER DEFAULT 0,
        results_json TEXT
    )''')
    conn.commit()
    conn.close()


@app.before_first_request
def setup():
    init_db()


def get_user_by_id(user_id):
    conn = sqlite3.connect('lms.db')
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, password_hash, speechace_user_id, test_taken, results_json FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_email(email):
    conn = sqlite3.connect('lms.db')
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, password_hash, speechace_user_id, test_taken, results_json FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_speechace_id(speechace_id):
    conn = sqlite3.connect('lms.db')
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, password_hash, speechace_user_id, test_taken, results_json FROM users WHERE speechace_user_id=?", (speechace_id,))
    row = cur.fetchone()
    conn.close()
    return row


@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template_string('''
    <h2>Welcome to the Speaking Test Platform</h2>
    <p><a href="{{ url_for('signup') }}">Sign Up</a> | <a href="{{ url_for('login') }}">Log In</a></p>
    ''')


@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or not email or not password:
            return 'All fields required', 400
        if get_user_by_email(email):
            return 'Email already registered', 400
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        speechace_user_id = f"u_{timestamp}_{len(name)}"
        password_hash = generate_password_hash(password)
        conn = sqlite3.connect('lms.db')
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name, email, password_hash, speechace_user_id) VALUES (?, ?, ?, ?)",
            (name, email, password_hash, speechace_user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template_string('''
    <h2>Sign Up</h2>
    <form method="post">
        <p><input name="name" placeholder="Full Name" required></p>
        <p><input type="email" name="email" placeholder="Email Address" required></p>
        <p><input type="password" name="password" placeholder="Password" required></p>
        <p><input type="submit" value="Sign Up"></p>
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Log In</a></p>
    ''')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        user = get_user_by_email(email)
        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        return 'Invalid credentials', 400
    return render_template_string('''
    <h2>Log In</h2>
    <form method="post">
        <p><input type="email" name="email" placeholder="Email Address" required></p>
        <p><input type="password" name="password" placeholder="Password" required></p>
        <p><input type="submit" value="Log In"></p>
    </form>
    <p>Don't have an account? <a href="{{ url_for('signup') }}">Sign Up</a></p>
    ''')


@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = get_user_by_id(user_id)
    name, speechace_user_id, test_taken, results_json = user[1], user[4], user[5], user[6]
    if not test_taken:
        return render_template_string('''
        <h2>Dashboard</h2>
        <p>Welcome, {{ name }}!</p>
        <p>You have not taken the test yet.</p>
        <a href="{{ url_for('start_test') }}">Start Test</a>
        <p><a href="{{ url_for('logout') }}">Log Out</a></p>
        ''', name=name)
    else:
        data = json.loads(results_json)
        scores = data.get('score', {})
        return render_template_string('''
        <h2>Dashboard</h2>
        <p>Welcome, {{ name }}!</p>
        <p>Your scores:</p>
        <ul>
            <li>Overall: {{ scores.get('overall') }}</li>
            <li>Pronunciation: {{ scores.get('pronunciation') }}</li>
            <li>Fluency: {{ scores.get('fluency') }}</li>
            <li>Vocabulary: {{ scores.get('vocab') }}</li>
            <li>Grammar: {{ scores.get('grammar') }}</li>
        </ul>
        <p><a href="{{ data.get('reportUrl') }}" target="_blank">Open Report</a></p>
        <p><a href="{{ url_for('logout') }}">Log Out</a></p>
        ''', name=name, scores=scores, data=data)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


@app.route('/start-test')
def start_test():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = get_user_by_id(user_id)
    speechace_user_id, name, email = user[4], user[1], user[2]
    oembed_url = os.environ.get('SPEECHACE_OEMBED_URL')
    key = os.environ.get('SPEECHACE_KEY')
    if not oembed_url or not key:
        return 'SpeechAce configuration missing', 500
    params = {
        'key': key,
        'app_user_id': speechace_user_id,
        'app_user_email': email,
        'app_user_fullname': name,
        'app_score_submission_url': request.url_root.rstrip('/') + url_for('submit_scores')
    }
    try:
        res = requests.get(oembed_url, params=params)
        if res.status_code != 200:
            return f'Error fetching test: {res.status_code}', 500
        iframe_html = res.json().get('html')
    except Exception as e:
        return f'Failed to fetch test: {e}', 500
    return render_template_string('''
    {{ iframe|safe }}
    <p><a href="{{ url_for('dashboard') }}">Return to Dashboard</a></p>
    ''', iframe=iframe_html)


@app.route('/submit-speechace-scores', methods=['POST'])
def submit_scores():
    data = request.get_json(force=True)
    if data.get('key') != os.environ.get('SPEECHACE_KEY'):
        return {'status':'error','message':'Invalid key'}, 403
    userId = data.get('userId')
    if not userId:
        return {'status':'error','message':'Missing userId'}, 400
    user = get_user_by_speechace_id(userId)
    if not user:
        return {'status':'error','message':'User not found'}, 404
    conn = sqlite3.connect('lms.db')
    cur = conn.cursor()
    cur.execute('UPDATE users SET test_taken=1, results_json=? WHERE speechace_user_id=?', (json.dumps(data), userId))
    conn.commit()
    conn.close()
    return {'status':'success'}


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host=os.environ.get('FLASK_HOST','0.0.0.0'), port=int(os.environ.get('FLASK_PORT',5000)))
