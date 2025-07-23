from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
import os
import uuid
import csv
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['CSV_FILE'] = 'students.csv'
app.config['DB_FILE'] = 'students.db'
app.secret_key = 'your_secret_key_here'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_index():
    return str(uuid.uuid4())[:8].upper()

# Add master admin credentials (for demo, hardcoded)
MASTER_ADMIN_USERNAME = 'masteradmin'
MASTER_ADMIN_PASSWORD = 'supersecret123'

# Extend DB initialization for admin keys
def init_db():
    with sqlite3.connect(app.config['DB_FILE']) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_index TEXT UNIQUE,
                name TEXT,
                surname TEXT,
                university TEXT,
                birth_place TEXT,
                address TEXT,
                parent_name TEXT,
                parent_details TEXT,
                photo_filename TEXT,
                class TEXT,
                dob TEXT,
                gender TEXT,
                religion TEXT,
                skills TEXT,
                father_name TEXT,
                mother_name TEXT,
                father_occupation TEXT,
                mother_occupation TEXT,
                registration_no INTEGER,
                date TEXT,
                drejtimi TEXT,
                dega TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS admin_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE,
                used INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

init_db()

@app.route('/')
def home():
    return redirect(url_for('admin_login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '')
        surname = request.form.get('surname', '')
        university = request.form.get('university', '')
        birth_place = request.form.get('birth_place', '')
        address = request.form.get('address', '')
        parent_name = request.form.get('parent_name', '')
        parent_details = request.form.get('parent_details', '')
        photo = request.files.get('photo')
        student_class = request.form.get('class', '')
        dob = request.form.get('dob', '')
        gender = request.form.get('gender', '')
        religion = request.form.get('religion', '')
        skills = request.form.get('skills', '')
        father_name = request.form.get('father_name', '')
        mother_name = request.form.get('mother_name', '')
        father_occupation = request.form.get('father_occupation', '')
        mother_occupation = request.form.get('mother_occupation', '')
        registration_no = request.form.get('registration_no', '')
        date = request.form.get('date', '')
        drejtimi = request.form.get('drejtimi', '')
        dega = request.form.get('dega', '')

        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(photo_path)
        else:
            return render_template('register.html', error='Invalid photo file.')

        student_index = generate_index()

        # Save to SQLite (update to include all new fields)
        with sqlite3.connect(app.config['DB_FILE']) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO students (
                    student_index, name, surname, university, birth_place, address, parent_name, parent_details, photo_filename,
                    class, dob, gender, religion, skills, father_name, mother_name, father_occupation, mother_occupation, registration_no, date, drejtimi, dega
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                student_index, name, surname, university, birth_place, address, parent_name, parent_details, filename,
                student_class, dob, gender, religion, skills, father_name, mother_name, father_occupation, mother_occupation, registration_no, date, drejtimi, dega
            ))
            conn.commit()

        return render_template('success.html', index=student_index, name=name)
    return render_template('register.html')

@app.route('/masteradmin/login', methods=['GET', 'POST'])
def masteradmin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == MASTER_ADMIN_USERNAME and password == MASTER_ADMIN_PASSWORD:
            session['masteradmin'] = True
            return redirect(url_for('generate_admin_key'))
        else:
            flash('Invalid master admin credentials.', 'danger')
    return render_template('masteradmin_login.html')

@app.route('/masteradmin/logout')
def masteradmin_logout():
    session.pop('masteradmin', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('masteradmin_login'))

def masteradmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('masteradmin'):
            return redirect(url_for('masteradmin_login'))
        return f(*args, **kwargs)
    return decorated_function

import secrets
@app.route('/admin/generate-key', methods=['GET', 'POST'])
@masteradmin_required
def generate_admin_key():
    new_key = None
    if request.method == 'POST':
        new_key = secrets.token_hex(4).upper()
        with sqlite3.connect(app.config['DB_FILE']) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO admin_keys (key, used) VALUES (?, 0)', (new_key,))
            conn.commit()
    return render_template('generate_admin_key.html', new_key=new_key)

# Update admin signup to require a valid key as username
@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        key = request.form['username']
        password = request.form['password']
        with sqlite3.connect(app.config['DB_FILE']) as conn:
            c = conn.cursor()
            c.execute('SELECT used FROM admin_keys WHERE key = ?', (key,))
            row = c.fetchone()
            if not row:
                flash('Invalid admin key.', 'danger')
                return render_template('admin_signup.html')
            if row[0]:
                flash('This key has already been used.', 'danger')
                return render_template('admin_signup.html')
            password_hash = generate_password_hash(password)
            try:
                c.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', (key, password_hash))
                c.execute('UPDATE admin_keys SET used = 1 WHERE key = ?', (key,))
                conn.commit()
                flash('Signup successful. Please log in.', 'success')
                return redirect(url_for('admin_login'))
            except sqlite3.IntegrityError:
                flash('This key has already been used as a username.', 'danger')
    return render_template('admin_signup.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(app.config['DB_FILE']) as conn:
            c = conn.cursor()
            c.execute('SELECT password_hash FROM admins WHERE username = ?', (username,))
            row = c.fetchone()
            if row and check_password_hash(row[0], password):
                session['admin'] = username
                return redirect(url_for('admin_page'))
            else:
                flash('Invalid username or password.', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('admin_login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_page():
    search_query = request.form.get('search', '') if request.method == 'POST' else ''
    with sqlite3.connect(app.config['DB_FILE']) as conn:
        c = conn.cursor()
        if search_query:
            c.execute("""
                SELECT id, student_index, name, surname, class, dob, gender, university, birth_place, address, parent_name, parent_details, photo_filename, registration_no, drejtimi
                FROM students
                WHERE name LIKE ? OR surname LIKE ? OR student_index LIKE ? OR CAST(registration_no AS TEXT) LIKE ? OR drejtimi LIKE ?
                ORDER BY id DESC
            """, (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
        else:
            c.execute("""
                SELECT id, student_index, name, surname, class, dob, gender, university, birth_place, address, parent_name, parent_details, photo_filename, registration_no, drejtimi
                FROM students
                ORDER BY id DESC
            """)
        students = c.fetchall()
    return render_template('admin_page.html', students=students, search_query=search_query)

@app.route('/admin/delete/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    with sqlite3.connect(app.config['DB_FILE']) as conn:
        c = conn.cursor()
        c.execute('DELETE FROM students WHERE id = ?', (student_id,))
        conn.commit()
    flash('Student deleted successfully.', 'success')
    return redirect(url_for('admin_page'))

@app.route('/admin/edit/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    with sqlite3.connect(app.config['DB_FILE']) as conn:
        c = conn.cursor()
        if request.method == 'POST':
            # Update student
            fields = [
                'name', 'surname', 'class', 'dob', 'gender', 'university', 'birth_place', 'address',
                'parent_name', 'parent_details'
            ]
            values = [request.form.get(f) for f in fields]
            c.execute(f'''
                UPDATE students SET
                    name=?, surname=?, class=?, dob=?, gender=?, university=?, birth_place=?, address=?,
                    parent_name=?, parent_details=?
                WHERE id=?
            ''', (*values, student_id))
            conn.commit()
            flash('Student updated successfully.', 'success')
            return redirect(url_for('admin_page'))
        else:
            c.execute('SELECT id, student_index, name, surname, class, dob, gender, university, birth_place, address, parent_name, parent_details, photo_filename FROM students WHERE id = ?', (student_id,))
            student = c.fetchone()
    return render_template('edit_student.html', student=student)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)
