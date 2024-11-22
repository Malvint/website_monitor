from gevent import monkey
monkey.patch_all()
from flask import Flask, render_template, request, redirect, url_for, session,jsonify,flash
from flask_mysqldb import MySQL
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from models import User, ROLES
from flask_socketio import SocketIO, emit
import uuid
from celery import Celery
from datetime import datetime, timedelta
import time
from passlib.hash import bcrypt
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from collections import defaultdict




app = Flask('__name__')
app.secret_key = 'group2_#@Project'
SocketIO = SocketIO(app)
celery = Celery(app.name, broker='redis://localhost:6379/0')
load_dotenv()

user_activity={}
login_attempts = defaultdict(int)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'guard'

mysql = MySQL(app)
login_manager = LoginManager(app)




@login_manager.user_loader
def load_user(user_id):
    if 'user_id' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, username, password, role FROM users WHERE id=%s", (session['user_id'],))
        user_data = cur.fetchone()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

def requires_role(role):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if 'role' in session and session['role'] != role:
                return redirect(url_for('home'))
            return func(*args, **kwargs)
        return wrapper
    return decorator


def send_email(subject, body, admin_emails):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = ''
    msg['To'] = ', '.join(admin_emails)
    
    with smtplib.SMTP('smtp.gmail.com',587) as smtp:
        smtp.starttls()
        smtp.login()
        smtp.send_message(msg)

       
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        login_attempts[username] += 1

        if username and password:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id, username, password, role FROM users WHERE username=%s", (username,))
            user_data = cur.fetchone()
            cur.close()

            if user_data and bcrypt.verify(password, user_data[2]):
                user = User(user_data[0], user_data[1], user_data[2], user_data[3])
                login_user(user)

                session_id = str(uuid.uuid4())

                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO sessions (user_id, session_id, created_at, updated_at, expires_at, data) VALUES (%s, %s, NOW(), NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR), %s)", (user.id, session_id, session.get('data')))

                cur.execute("INSERT INTO user_activity (username, login_timestamp, last_active) VALUES (%s, NOW(), NOW())", (user.username,))

                mysql.connection.commit()
                cur.close()

                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                session['session_id'] = session_id
                session['data'] = session.get('data', None)

                if user.role == 'user':
                    subject = 'New User Login'
                    body = f'A user with username "{user.username}" has logged in.'
                    admin_emails = []  
                    send_email(subject, body, admin_emails)
                    SocketIO.emit('user_activity', {'username': user.username, 'role': user.role}, room='all')

                    return redirect(url_for('user'))
                else:
                    subject = 'New User Login'
                    body = f'A user with username "{user.username}" has logged in.'
                    admin_emails = [admins email address]  
                    send_email(subject, body, admin_emails)
                    SocketIO.emit('user_activity', {'username': user.username, 'role': user.role}, room='all')
                    return redirect(url_for('admin'))
                
            elif login_attempts[username] > 2:
                
                subject = 'Suspicious Login Attempt'
                body = f'A user with username "{username}" has tried to log in more than three times.'
                admin_emails = ["admins email address"]  
                send_email(subject, body, admin_emails)

                flash('Too many failed login attempts. Please contact the administrator.', category='error')
            else:
                return render_template('login.html', error='Invalid username or password', username=username)

    return render_template('login.html')

@app.route('/logout', methods=['POST','GET'])
@login_required
def logout():
    username = current_user.username
    role = current_user.role

    
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM sessions WHERE user_id=%s AND session_id=%s", (session['user_id'], session['session_id']))
    
    cur.execute("UPDATE user_activity SET logout_timestamp = NOW() WHERE username = %s ORDER BY id DESC LIMIT 1", (username,))
    
    SocketIO.emit('user_logged_out',  room='all')
    
    mysql.connection.commit()
    cur.close()

    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('session_id', None)
    session.pop('data', None)
    
    
    logout_user()
    return redirect(url_for('home'))


@app.route('/logged_in_users')
def logged_in_users():
    logged_in_users = get_logged_in_users(mysql)
    return render_template('active_users.html', users=logged_in_users)

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/admin')
@login_required
def admin():
    user_count = count_users(mysql)
    active_users= count_active_users(mysql) 
    return render_template('admin.html', user_count=user_count, active_users=active_users)

    
@app.route('/user')
@login_required
def user():
    return render_template('user.html')

@app.route('/viewusers')
@login_required
def view_users():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users")
        users = cur.fetchall()
        cur.close()

        return render_template('view_users.html', users=users)
    
    except Exception as e:
        print("Error retrieving users from the database:", e)
        return 'Error retrieving users from the database.', e     


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT username FROM users WHERE username=%s", (username,))
            existing_user = cur.fetchone()
            cur.close()

            if existing_user:
                flash('Username already exists!!!', category='error')
                return render_template('signup.html', error='Username already exists!!!', username=username)
            elif len(email) < 4:
                flash('Email must be greater than 4 characters.', category='error')
                return render_template('signup.html', error='Your email is too short!!!', email=username)
            elif len(username) < 4:
                flash('Username must be greater than 3 characters.', category='error')
                return render_template('signup.html', error='Username is too short it must be greater than 3 characters!! ', username=username)
            elif len(password) < 8:
                 flash('Password must be at least 8 characters.', category='error')
                 return render_template('signup.html', error='Password is too weak!!!')
            elif password != confirm_password:
                flash('Passwords don\'t match.', category='error')
                return render_template('signup.html', error='Passwords do not match!!!')

            else:
                hashed_password = bcrypt.hash(password)
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)", (username, email, hashed_password, role))
                mysql.connection.commit()
                cur.close()
                
                subject = 'New User Signup'
                body = f'''A new user has signed up with the following details: Username: {username} Email: {email} Role: {role}'''
                admin_emails = [] 
                send_email(subject, body, admin_emails)

                SocketIO.emit("New user created: {username} (Role: {role})", room='all')

                session['username'] = username
                session['role'] = role
                return redirect(url_for('login'))
        except mysql.connection.IntegrityError as e:
            if 'Duplicate entry' in str(e):
                flash('Username or email already exists.', category='error')
            else:
                raise e

    return render_template('signup.html', role=ROLES)


@SocketIO.on('connect')
def handle_connect():
    if current_user.is_authenticated and current_user.role == 'admin':
        print(f"Admin {current_user.username} connected.")
        emit('user_activity', {'username': current_user.username, 'role': 'admin'}, broadcast=True)
    elif current_user.is_authenticated:
        print(f"User {current_user.username} connected.")
        emit('user_activity', {'username': current_user.username, 'role': 'user'}, broadcast=True)
    else:
        print("Anonymous user connected.")

@SocketIO.on('user_reload')
def handle_user_reload(data):
    username = data['username']
    print(f"User {username} reloaded the page.")
    SocketIO.emit('user_reload', {'username': username}, room='admin')




def count_users(mysql):
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT COUNT(*) FROM users")  

        user_counts = cur.fetchone()
        user_count=user_counts[0]
        cur.close()
        return user_count

    except Exception as e:
        print("Error retrieving user count:", e)
        return 0  

def count_active_users(mysql):
    try:
        while True:
            cur = mysql.connection.cursor()
            cur.execute("SELECT COUNT(*) FROM sessions WHERE updated_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)")
            active_users = cur.fetchone()[0]
            cur.close()
            time.sleep(1)
            
            return active_users
    except Exception as e:
        print("Error retrieving user count:", e)
        return 0

    
def get_logged_in_users(mysql):
    time_limit = datetime.now() - timedelta(minutes=10)

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT users.username, users.role, sessions.created_at
        FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE sessions.updated_at >= %s
    """, (time_limit,))
    logged_in_users = cur.fetchall()
    cur.close()

    return logged_in_users

@SocketIO.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    
@SocketIO.on('user_download')
def handle_user_download(data):
    username = data['username']
    file_name = data['file_name']

    if username not in user_activity:
        user_activity[username] = {
            'downloads': [],
            'scrolls': []
        }

    user_activity[username]['downloads'].append({
        'file_name': file_name,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

    
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO user_activity (username, activity, timestamp) VALUES (%s, %s, NOW())", (username, f"Downloaded file: {file_name}"))
    mysql.connection.commit()
    cur.close()

    
    SocketIO.emit('user_download', {'username': username, 'file_name': file_name}, broadcast=True)

    
    return user_activity[username]

@SocketIO.on('user_scroll')
def handle_user_scroll(data):
    username = data['username']
    scroll_position = data['scroll_position']

    if username not in user_activity:
        user_activity[username] = {
            'downloads': [],
            'scrolls': []
        }

    user_activity[username]['scrolls'].append({
        'scroll_position': scroll_position,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

   
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO user_activity (username, activity, timestamp) VALUES (%s, %s, NOW())", (username, f"Scrolled to position: {scroll_position}"))
    mysql.connection.commit()
    cur.close()

   
    SocketIO.emit('user_scroll', {'username': username, 'scroll_position': scroll_position}, broadcast=True)

   
    return user_activity[username]



if __name__ == '__main__':
    app.run(debug=True)
