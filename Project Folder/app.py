# --- File: app.py ---
# This Flask application now serves as a Progressive Web App (PWA)
# with a service worker and manifest file.

from flask import Flask, render_template, request, redirect, url_for, session, g, send_from_directory
import json
import hashlib
from functools import wraps
import os

# --- User Data & Hashing Configuration ---
USER_DATA_JSON = """
{
    "student1": {
        "id": 1,
        "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "role": "student"
    },
    "teacher1": {
        "id": 2,
        "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "role": "teacher"
    },
    "admin1": {
        "id": 3,
        "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "role": "admin"
    }
}
"""

REWARD_HISTORY = {
    1: [
        {'reward': 'Free Lunch Pass', 'awarded_by_teacher': 'Ms. Davis', 'timestamp': '2024-05-20'},
        {'reward': 'Homework Pass', 'awarded_by_teacher': 'Mr. Smith', 'timestamp': '2024-06-01'}
    ]
}

def get_users():
    """Returns the parsed user data dictionary."""
    return json.loads(USER_DATA_JSON)

def hash_password(password):
    """
    Hashes a password using SHA256.
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

app = Flask(__name__, static_url_path='/static')
app.secret_key = 'your_super_secret_key_here'

# --- PWA File Serving Routes ---
@app.route('/service-worker.js')
def serve_service_worker():
    """Serves the service worker file."""
    return send_from_directory('.', 'service-worker.js', mimetype='application/javascript')

@app.route('/manifest.json')
def serve_manifest():
    """Serves the manifest file."""
    return send_from_directory('.', 'manifest.json', mimetype='application/manifest+json')

@app.after_request
def add_no_cache_headers(response):
    """
    Adds headers to prevent the browser from caching pages, forcing the
    service worker to intercept and use the Network First strategy.
    """
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.before_request
def check_session():
    """Stores user data in a global object 'g' for easy access in templates."""
    g.user = None
    if 'username' in session:
        users = get_users()
        username = session['username']
        user_data = users.get(username)
        if user_data:
            g.user = user_data
            g.user['username'] = username

@app.errorhandler(404)
def page_not_found(e):
    """
    Handles 404 Not Found errors by redirecting the user.
    If the user is logged in, they are sent to their dashboard.
    Otherwise, they are sent to the login page.
    This also handles redirection for offline users.
    """
    if 'username' in session:
        # If logged in, redirect to dashboard.
        return redirect(url_for('dashboard'))
    else:
        # If not logged in, redirect to login page.
        return redirect(url_for('login'))

def login_required(func):
    """A decorator to protect routes that require a logged-in user."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def role_required(allowed_roles):
    """A decorator to protect routes that require a specific role."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'username' not in session or session.get('role') not in allowed_roles:
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/offline')
def offline():
    """Route to serve the static offline page."""
    return render_template('offline.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    """
    Handles user login and session creation.
    If a user is already logged in, this route redirects them to their dashboard,
    enforcing that the login page is only accessible when the user is logged out.
    """
    # If the user is already logged in, redirect them to the dashboard.
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        users = get_users()
        user = users.get(username)

        if user and user['password_hash'] == hash_password(password) and user['role'] == role:
            session.clear()
            session['username'] = username
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username, password, or role.')
    
    # For a GET request when not logged in, show the login form.
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs the user out and clears the session."""
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """A central dashboard that redirects to the appropriate page based on user role."""
    user_role = session.get('role')
    if user_role == 'student':
        return redirect(url_for('student_dashboard'))
    elif user_role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    elif user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('logout'))

@app.route('/student_dashboard')
@role_required(allowed_roles=['student'])
def student_dashboard():
    """Displays the rewards the student has earned."""
    student_id = session.get('user_id')
    rewards_earned = REWARD_HISTORY.get(student_id, [])
    return render_template('student_dashboard.html', rewards=rewards_earned)

@app.route('/teacher_dashboard', methods=['GET', 'POST'])
@role_required(allowed_roles=['teacher'])
def teacher_dashboard():
    """Allows teachers to search for students and view their award history."""
    users = get_users()
    students = [{'id': user['id'], 'username': username} for username, user in users.items() if user['role'] == 'student']
    student_history = None
    selected_student = None

    if request.method == 'POST':
        student_id = int(request.form.get('student_id'))
        if student_id:
            student_history = REWARD_HISTORY.get(student_id, [])
            selected_student_name = next((s['username'] for s in students if s['id'] == student_id), None)
            if selected_student_name:
                selected_student = selected_student_name

    return render_template('teacher_dashboard.html', students=students, student_history=student_history, selected_student=selected_student)

@app.route('/admin_dashboard')
@role_required(allowed_roles=['admin'])
def admin_dashboard():
    """Displays key statistics for administrators."""
    stats = {
        'total_students': 150,
        'active_teachers': 5,
        'rewards_redeemed': 42,
        'popular_reward': 'Free Lunch Pass',
        'points_awarded': 15000,
        'most_active_teacher': 'Ms. Davis'
    }
    return render_template('admin_dashboard.html', stats=stats)

if __name__ == '__main__':
    print("--- Test Credentials ---")
    print("Username: student1, Password: T1g3r_S1@m_P0unds_L1k3_!t, Role: student")
    print("Username: teacher1, Password: T1g3r_S1@m_P0unds_L1k3_!t, Role: teacher")
    print("Username: admin1, Password: T1g3r_S1@m_P0unds_L1k3_!t, Role: admin")
    print("------------------------")
    app.run(debug=True)
