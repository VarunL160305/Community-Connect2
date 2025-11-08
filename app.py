from flask import Flask, render_template, request, redirect, session, g
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash  # Added for password hashing

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "data.db")

app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = "data.db"
DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.before_request
def ensure_db_initialized():
    db = get_db()
    try:
        # Try selecting from a known table to test if the DB exists
        db.execute("SELECT 1 FROM users LIMIT 1")
    except sqlite3.OperationalError:
        print("Database not found — initializing now...")
        init_db()

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password TEXT,
                role TEXT,
                class_name TEXT,
                section TEXT
            );
            CREATE TABLE IF NOT EXISTS allowed_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS timetable (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                day TEXT,
                periods TEXT
            );
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                day TEXT,
                subjects TEXT
            );
        ''')
        cur = db.execute("SELECT * FROM users WHERE role='hod'")
        if not cur.fetchone():
            hashed_pwd = generate_password_hash('admin123')  # Hash default password
            db.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                       ('hod@admin.com', hashed_pwd, 'hod'))
        db.commit()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        if user and check_password_hash(user['password'], password):  # Check hashed password
            session['email'] = user['email']
            session['role'] = user['role']
            if user['role'] == 'hod':
                return redirect('/hod_dashboard')
            elif user['role'] == 'staff':
                cur = db.execute("SELECT * FROM timetable WHERE email = ?", (email,))
                if cur.fetchone():
                    rows = db.execute("SELECT day, periods FROM timetable WHERE email=?", (email,)).fetchall()
                    timetable = {row['day']: row['periods'].split('|') for row in rows}
                    session['timetable'] = timetable
                    return redirect('/timetable')
                else:
                    return redirect('/subject_input')
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    password = generate_password_hash(request.form['password'])  # Hash password
    class_name = request.form['class_name']
    section = request.form['section']
    db = get_db()
    cur = db.execute("SELECT * FROM allowed_emails WHERE email=?", (email,))
    allowed = cur.fetchone()
    if not allowed:
        return render_template('login.html', error="Email not allowed for registration")
    try:
        db.execute("INSERT INTO users (email, password, role, class_name, section) VALUES (?, ?, 'staff', ?, ?)",
                   (email, password, class_name, section))
        db.commit()
        return render_template('login.html', success="Registration successful. You can now log in.")
    except sqlite3.IntegrityError:
        return render_template('login.html', error="Email already registered")

@app.route('/hod_dashboard', methods=['GET'])
def hod_dashboard():
    if 'role' not in session or session['role'] != 'hod':
        return redirect('/')
    db = get_db()
    allowed_emails = db.execute("SELECT email FROM allowed_emails").fetchall()
    staff_users = db.execute("SELECT email, class_name, section FROM users WHERE role='staff'").fetchall()
    return render_template('hod_dashboard.html', emails=[e['email'] for e in allowed_emails], staff_users=staff_users)

@app.route('/add_email', methods=['POST'])
def add_email():
    if 'role' not in session or session['role'] != 'hod':
        return redirect('/')
    email = request.form['email']
    db = get_db()
    try:
        db.execute("INSERT INTO allowed_emails (email) VALUES (?)", (email,))
        db.commit()
    except sqlite3.IntegrityError:
        pass
    return redirect('/hod_dashboard')

@app.route('/remove_email', methods=['POST'])
def remove_email():
    if 'role' not in session or session['role'] != 'hod':
        return redirect('/')
    email = request.form['email']
    db = get_db()
    db.execute("DELETE FROM allowed_emails WHERE email = ?", (email,))
    db.execute("DELETE FROM users WHERE email = ?", (email,))
    db.execute("DELETE FROM timetable WHERE email = ?", (email,))
    db.execute("DELETE FROM subjects WHERE email = ?", (email,))
    db.commit()
    return redirect('/hod_dashboard')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        email = request.form['email']
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        db = get_db()
        cur = db.execute("SELECT * FROM allowed_emails WHERE email=?", (email,))
        allowed = cur.fetchone()
        if not allowed:
            return render_template("change_password.html", error="Email not approved by HOD")
        cur = db.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cur.fetchone()
        if not user or not check_password_hash(user['password'], old_password):  # Verify old password
            return render_template("change_password.html", error="Incorrect old password")
        if old_password == new_password:
            return render_template("change_password.html", error="New password must be different from old password")
        hashed = generate_password_hash(new_password)  # Hash new password
        db.execute("UPDATE users SET password=? WHERE email=?", (hashed, email))
        db.commit()
        return redirect('/')
    return render_template("change_password.html")

@app.route('/subject_input', methods=['GET', 'POST'])
def subject_input():
    if 'role' not in session or session['role'] != 'staff':
        return redirect('/')

    db = get_db()

    if request.method == 'POST':
        subjects = {}
        for day in DAYS:
            subjects[day] = []
            for i in range(8):
                subject = request.form.get(f"{day}_{i}", "").strip()
                subjects[day].append(subject)
        session['subjects'] = subjects

        db.execute("DELETE FROM subjects WHERE email=?", (session['email'],))
        for day in DAYS:
            line = '|'.join(subjects[day])
            db.execute("INSERT INTO subjects (email, day, subjects) VALUES (?, ?, ?)", (session['email'], day, line))
        db.commit()

        return redirect('/teacher_input')

    prefill = session.get('subjects')
    if not prefill:
        rows = db.execute("SELECT day, subjects FROM subjects WHERE email=?", (session['email'],)).fetchall()
        if rows:
            prefill = {row['day']: row['subjects'].split('|') for row in rows}
            session['subjects'] = prefill
        else:
            prefill = {day: [""] * 8 for day in DAYS}

    return render_template('subject_input.html', days=DAYS, prefill=prefill)

@app.route('/teacher_input', methods=['GET', 'POST'])
def teacher_input():
    if 'subjects' not in session:
        return redirect('/')

    if request.method == 'POST':
        teacher_map = {}
        for subject in session['unique_subjects']:
            teacher_name = request.form.get(subject, "").strip()
            teacher_map[subject] = teacher_name

        session['teacher_map'] = teacher_map

        timetable = {}
        for day in DAYS:
            timetable[day] = []
            for i in range(8):
                subject = session['subjects'][day][i]
                teacher = teacher_map.get(subject, "") if subject else ""
                timetable[day].append(f"{subject} ({teacher})" if subject else "")

        session['timetable'] = timetable

        db = get_db()
        db.execute("DELETE FROM timetable WHERE email=?", (session['email'],))
        for day in DAYS:
            line = '|'.join(timetable[day])
            db.execute("INSERT INTO timetable (email, day, periods) VALUES (?, ?, ?)", (session['email'], day, line))
        db.commit()

        return redirect('/timetable')

    all_subjects = []
    for subjects in session['subjects'].values():
        all_subjects.extend(subjects)
    unique_subjects = sorted(set(filter(None, all_subjects)))
    session['unique_subjects'] = unique_subjects

    prefill = session.get('teacher_map', {})
    return render_template('teacher_input.html', unique_subjects=unique_subjects, prefill=prefill)

@app.route('/timetable')
def timetable():
    if 'timetable' not in session:
        return redirect('/')
    return render_template('timetable.html', timetable=session['timetable'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    try:
        init_db()  # Always ensures tables exist
    except Exception as e:
        print("Error initializing database:", e)
    app.run(debug=True)
