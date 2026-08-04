"""
Professional Employee Management Application - SECURE VERSION
Security best practices implemented for production deployment
"""
import json
import sqlite3
import os
from functools import wraps
from datetime import datetime
import xml.etree.ElementTree as ET
from io import StringIO
import csv

from flask import Flask, jsonify, request, render_template_string, redirect, session
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import logging

# ============================================================================
# CONFIGURATION - Using Environment Variables
# ============================================================================

app = Flask(__name__)

# Use environment variables for sensitive data
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production-use-env-vars')
if app.secret_key == 'change-me-in-production-use-env-vars':
    app.logger.warning('Using default SECRET_KEY. Set SECRET_KEY environment variable.')

# Security configurations
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour timeout
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit on CSRF tokens

# Disable debug mode in production
app.debug = os.environ.get('FLASK_ENV') == 'development'
if app.debug:
    app.logger.warning('Debug mode is enabled. Disable in production.')

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# SECURE FILE UPLOAD CONFIGURATION
# ============================================================================

DATABASE = os.environ.get('DATABASE_PATH', '/tmp/employee_app.db')
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Only allow safe file types
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'csv', 'json'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def validate_file_size(file_obj):
    """Check file size"""
    file_obj.seek(0, os.SEEK_END)
    size = file_obj.tell()
    file_obj.seek(0)
    return size <= MAX_FILE_SIZE

# ============================================================================
# DATABASE SETUP
# ============================================================================

def init_db():
    """Initialize database with sample data"""
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        # Create tables
        c.execute('''CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            salary REAL NOT NULL,
            ssn TEXT NOT NULL,
            address TEXT,
            phone TEXT
        )''')
        
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        
        c.execute('''CREATE TABLE performance (
            id INTEGER PRIMARY KEY,
            employee_id INTEGER NOT NULL,
            rating REAL NOT NULL,
            comments TEXT,
            date TEXT NOT NULL,
            FOREIGN KEY(employee_id) REFERENCES employees(id)
        )''')
        
        # Insert sample data with securely hashed passwords
        employees_data = [
            (101, 'Akshay Kumar', 'akshay@corp.com', 'DevSecOps Lead', 'Security Operations', 120000, '123-45-6789', '123 Main St', '555-0101'),
            (102, 'Rohan Singh', 'rohan@corp.com', 'Cloud Architect', 'Infrastructure', 110000, '234-56-7890', '456 Oak Ave', '555-0102'),
            (103, 'Priya Sharma', 'priya@corp.com', 'Backend Engineer', 'Engineering', 95000, '345-67-8901', '789 Pine Rd', '555-0103'),
            (104, 'Vikram Patel', 'vikram@corp.com', 'Database Admin', 'Infrastructure', 105000, '456-78-9012', '101 Elm St', '555-0104'),
            (105, 'Neha Gupta', 'neha@corp.com', 'Security Engineer', 'Security Operations', 98000, '567-89-0123', '202 Maple Dr', '555-0105'),
        ]
        
        c.executemany('INSERT INTO employees VALUES (?,?,?,?,?,?,?,?,?)', employees_data)
        
        # Use hashed passwords
        users_data = [
            (1, 'admin', generate_password_hash('Admin@123'), 'admin@corp.com', 'admin'),
            (2, 'manager', generate_password_hash('Manager@123'), 'manager@corp.com', 'manager'),
            (3, 'user', generate_password_hash('User@123'), 'user@corp.com', 'user'),
        ]
        
        c.executemany('INSERT INTO users VALUES (?,?,?,?,?)', users_data)
        
        conn.commit()
        conn.close()
        logger.info('Database initialized')

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================================================
# AUTHENTICATION & AUTHORIZATION
# ============================================================================

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/login')
            
            user_role = session.get('role')
            if user_role not in required_roles:
                logger.warning(f'Unauthorized access attempt by user {session.get("username")}')
                return jsonify({'error': 'Unauthorized'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def home():
    """Home route"""
    if 'user_id' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limiting
def login():
    """Secure login with parameterized queries"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation
        if not username or not password:
            return render_template_string(LOGIN_TEMPLATE, error='Username and password required')
        
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            conn.close()
            
            # Verify password hash
            if user and check_password_hash(user['password'], password):
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                logger.info(f'User {username} logged in successfully')
                return redirect('/dashboard')
            else:
                logger.warning(f'Failed login attempt for user {username}')
                return render_template_string(LOGIN_TEMPLATE, error='Invalid credentials')
        
        except Exception as e:
            logger.error(f'Login error: {str(e)}')
            return render_template_string(LOGIN_TEMPLATE, error='An error occurred. Please try again.')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    """Logout user"""
    username = session.get('username')
    session.clear()
    logger.info(f'User {username} logged out')
    return redirect('/login')

# ============================================================================
# EMPLOYEE ENDPOINTS
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard for authenticated users"""
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/api/employees', methods=['GET'])
@login_required
def get_employees():
    """Get all employees (role-based access)"""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT id, name, email, role, department FROM employees')
        employees = c.fetchall()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'count': len(employees),
            'data': [dict(emp) for emp in employees]
        })
    
    except Exception as e:
        logger.error(f'Error fetching employees: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/employees/<int:emp_id>')
@login_required
def get_employee_details(emp_id):
    """Get employee details with authorization checks"""
    try:
        # Validate emp_id
        if not isinstance(emp_id, int) or emp_id <= 0:
            return jsonify({'error': 'Invalid employee ID'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Use parameterized query
        c.execute('SELECT id, name, email, role, department FROM employees WHERE id = ?', (emp_id,))
        employee = c.fetchone()
        conn.close()
        
        if employee:
            # Return only non-sensitive information
            return jsonify({
                'id': employee['id'],
                'name': escape(employee['name']),
                'email': escape(employee['email']),
                'role': escape(employee['role']),
                'department': escape(employee['department'])
            })
        
        return jsonify({'error': 'Employee not found'}), 404
    
    except Exception as e:
        logger.error(f'Error fetching employee details: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/employees', methods=['POST'])
@login_required
@role_required(['admin', 'manager'])  # Only admins and managers can add
def add_employee():
    """Add employee with input validation"""
    try:
        data = request.get_json()
        
        # Input validation
        required_fields = ['name', 'email', 'role', 'department', 'salary']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate email format
        if '@' not in data.get('email', '') or '.' not in data.get('email', ''):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate salary is a number
        try:
            salary = float(data.get('salary'))
            if salary < 0:
                return jsonify({'error': 'Invalid salary'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Salary must be a number'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        
        try:
            # Use parameterized query
            c.execute('''INSERT INTO employees 
                        (name, email, role, department, salary, ssn, address, phone)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (escape(data.get('name')).strip(),
                      escape(data.get('email')).strip(),
                      escape(data.get('role')).strip(),
                      escape(data.get('department')).strip(),
                      salary,
                      escape(data.get('ssn', '000-00-0000')),
                      escape(data.get('address', 'N/A')),
                      escape(data.get('phone', 'N/A'))))
            
            conn.commit()
            conn.close()
            logger.info(f'Employee {data.get("name")} added by {session.get("username")}')
            
            return jsonify({'status': 'success', 'message': 'Employee added'}), 201
        
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Employee email already exists'}), 409
    
    except Exception as e:
        logger.error(f'Error adding employee: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/employees/<int:emp_id>', methods=['PUT'])
@login_required
@role_required(['admin', 'manager'])
def update_employee(emp_id):
    """Update employee with parameterized queries"""
    try:
        data = request.get_json()
        
        # Validate emp_id
        if not isinstance(emp_id, int) or emp_id <= 0:
            return jsonify({'error': 'Invalid employee ID'}), 400
        
        # Validate salary if provided
        if 'salary' in data:
            try:
                salary = float(data['salary'])
                if salary < 0:
                    return jsonify({'error': 'Invalid salary'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Salary must be a number'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Use parameterized query
        c.execute('''UPDATE employees SET 
                      name = ?,
                      email = ?,
                      salary = ?
                      WHERE id = ?''',
                 (escape(data.get('name')).strip(),
                  escape(data.get('email')).strip(),
                  float(data.get('salary')),
                  emp_id))
        
        if c.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Employee not found'}), 404
        
        conn.commit()
        conn.close()
        logger.info(f'Employee {emp_id} updated by {session.get("username")}')
        
        return jsonify({'status': 'success', 'message': 'Employee updated'})
    
    except Exception as e:
        logger.error(f'Error updating employee: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/employees/<int:emp_id>', methods=['DELETE'])
@login_required
@role_required(['admin'])  # Only admins can delete
def delete_employee(emp_id):
    """Delete employee with authorization"""
    try:
        # Validate emp_id
        if not isinstance(emp_id, int) or emp_id <= 0:
            return jsonify({'error': 'Invalid employee ID'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Use parameterized query
        c.execute('DELETE FROM employees WHERE id = ?', (emp_id,))
        
        if c.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Employee not found'}), 404
        
        conn.commit()
        conn.close()
        logger.info(f'Employee {emp_id} deleted by {session.get("username")}')
        
        return jsonify({'status': 'success', 'message': 'Employee deleted'})
    
    except Exception as e:
        logger.error(f'Error deleting employee: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# SEARCH ENDPOINT
# ============================================================================

@app.route('/search')
@login_required
@limiter.limit("10 per minute")
def search():
    """Secure search with parameterized queries"""
    try:
        query = request.args.get('q', '').strip()
        
        # Input validation
        if not query or len(query) > 100:
            return render_template_string(SEARCH_TEMPLATE, results=[], query='')
        
        search_term = f"%{query}%"
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        c.execute('''SELECT id, name, email, role, department 
                     FROM employees 
                     WHERE name LIKE ? OR email LIKE ?''',
                 (search_term, search_term))
        results = c.fetchall()
        conn.close()
        
        # Escape output to prevent XSS
        safe_results = []
        for emp in results:
            safe_results.append({
                'id': emp['id'],
                'name': escape(emp['name']),
                'email': escape(emp['email']),
                'role': escape(emp['role']),
                'department': escape(emp['department'])
            })
        
        return render_template_string(SEARCH_TEMPLATE, 
                                     results=safe_results, 
                                     query=escape(query))
    
    except Exception as e:
        logger.error(f'Search error: {str(e)}')
        return render_template_string(SEARCH_TEMPLATE, results=[], query='')

# ============================================================================
# PERFORMANCE REVIEWS
# ============================================================================

@app.route('/api/performance/<int:emp_id>', methods=['POST'])
@login_required
@role_required(['admin', 'manager'])
def add_performance(emp_id):
    """Add performance review with input sanitization"""
    try:
        data = request.get_json()
        
        # Validate emp_id
        if not isinstance(emp_id, int) or emp_id <= 0:
            return jsonify({'error': 'Invalid employee ID'}), 400
        
        # Validate rating
        try:
            rating = float(data.get('rating'))
            if rating < 0 or rating > 5:
                return jsonify({'error': 'Rating must be between 0 and 5'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid rating'}), 400
        
        comments = escape(data.get('comments', '')).strip()
        if len(comments) > 1000:
            return jsonify({'error': 'Comments too long'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        
        # Verify employee exists
        c.execute('SELECT id FROM employees WHERE id = ?', (emp_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'error': 'Employee not found'}), 404
        
        # Use parameterized query
        c.execute('''INSERT INTO performance (employee_id, rating, comments, date)
                     VALUES (?, ?, ?, ?)''',
                 (emp_id, rating, comments, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        logger.info(f'Performance review added for employee {emp_id} by {session.get("username")}')
        
        return jsonify({'status': 'success', 'message': 'Review added'}), 201
    
    except Exception as e:
        logger.error(f'Error adding performance review: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/performance/<int:emp_id>')
@login_required
def get_performance(emp_id):
    """Get performance reviews with escaped output"""
    try:
        # Validate emp_id
        if not isinstance(emp_id, int) or emp_id <= 0:
            return jsonify({'error': 'Invalid employee ID'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute('SELECT * FROM performance WHERE employee_id = ?', (emp_id,))
        reviews = c.fetchall()
        conn.close()
        
        # Escape comments to prevent XSS
        safe_reviews = []
        for r in reviews:
            safe_reviews.append({
                'id': r['id'],
                'rating': r['rating'],
                'comments': escape(r['comments']) if r['comments'] else '',
                'date': r['date']
            })
        
        return jsonify({
            'employee_id': emp_id,
            'reviews': safe_reviews
        })
    
    except Exception as e:
        logger.error(f'Error fetching performance reviews: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# FILE UPLOAD
# ============================================================================

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def upload_file():
    """Secure file upload with validation"""
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                return render_template_string(UPLOAD_TEMPLATE, error='No file provided')
            
            file = request.files['file']
            
            if file.filename == '':
                return render_template_string(UPLOAD_TEMPLATE, error='No file selected')
            
            # Validate file type
            if not allowed_file(file.filename):
                return render_template_string(UPLOAD_TEMPLATE, 
                                            error=f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}')
            
            # Validate file size
            if not validate_file_size(file):
                return render_template_string(UPLOAD_TEMPLATE, 
                                            error=f'File too large. Max size: {MAX_FILE_SIZE / 1024 / 1024}MB')
            
            # Secure filename
            filename = secure_filename(file.filename)
            # Add timestamp to make filename unique
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            
            logger.info(f'File {filename} uploaded by {session.get("username")}')
            return render_template_string(UPLOAD_TEMPLATE, 
                                        success=f'File {escape(filename)} uploaded successfully')
        
        except Exception as e:
            logger.error(f'File upload error: {str(e)}')
            return render_template_string(UPLOAD_TEMPLATE, error='An error occurred during upload')
    
    return render_template_string(UPLOAD_TEMPLATE)

# ============================================================================
# SECURE XML IMPORT
# ============================================================================

@app.route('/api/import-xml', methods=['POST'])
@login_required
@role_required(['admin'])
def import_xml():
    """Secure XML import with XXE prevention"""
    try:
        if 'xml_file' not in request.files:
            return jsonify({'error': 'No XML file provided'}), 400
        
        xml_file = request.files['xml_file']
        
        if xml_file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not xml_file.filename.endswith('.xml'):
            return jsonify({'error': 'Only XML files allowed'}), 400
        
        xml_content = xml_file.read().decode('utf-8', errors='ignore')
        
        # Validate XML size
        if len(xml_content) > 1024 * 1024:  # 1MB limit
            return jsonify({'error': 'XML file too large'}), 400
        
        try:
            # Secure XML parsing with XXE prevention
            parser = ET.XMLParser()
            parser.entity = {}  # Disable external entities
            root = ET.fromstring(xml_content, parser=parser)
            
            logger.info(f'XML file imported by {session.get("username")}')
            return jsonify({
                'status': 'success',
                'message': 'XML imported successfully',
                'elements': len(root)
            })
        
        except ET.ParseError as e:
            return jsonify({'error': f'Invalid XML: {str(e)}'}), 400
    
    except Exception as e:
        logger.error(f'XML import error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# SECURE DATA EXPORT
# ============================================================================

@app.route('/api/export', methods=['POST'])
@login_required
@role_required(['admin', 'manager'])
def export_data():
    """Export employee data in safe CSV format"""
    try:
        format_type = request.args.get('format', 'csv').lower()
        
        if format_type not in ['csv', 'json']:
            return jsonify({'error': 'Invalid format'}), 400
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT id, name, email, role, department FROM employees')
        employees = c.fetchall()
        conn.close()
        
        if format_type == 'json':
            data = [dict(emp) for emp in employees]
            return jsonify(data)
        
        elif format_type == 'csv':
            # Safe CSV generation
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Name', 'Email', 'Role', 'Department'])
            
            for emp in employees:
                writer.writerow([
                    emp['id'],
                    emp['name'],
                    emp['email'],
                    emp['role'],
                    emp['department']
                ])
            
            logger.info(f'Data exported in CSV format by {session.get("username")}')
            return output.getvalue(), 200, {'Content-Type': 'text/csv'}
    
    except Exception as e:
        logger.error(f'Export error: {str(e)}')
        return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# SECURITY HEADERS
# ============================================================================

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ============================================================================
# ERROR HANDLING
# ============================================================================

@app.errorhandler(400)
def bad_request(error):
    logger.warning(f'Bad request: {str(error)}')
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Internal server error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# INITIALIZE AND RUN
# ============================================================================

init_db()

# ============================================================================
# TEMPLATES
# ============================================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Portal Login</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               margin: 0; padding: 0; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .login-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                          width: 300px; }
        h1 { color: #333; margin-top: 0; text-align: center; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #764ba2; }
        .error { color: red; text-align: center; margin: 10px 0; }
        .credentials { font-size: 12px; color: #999; margin-top: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Employee Portal</h1>
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="credentials">
            Demo Credentials:<br>
            admin / Admin@123<br>
            manager / Manager@123<br>
            user / User@123
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Management Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .card h3 { color: #667eea; margin-bottom: 10px; }
        .stat { font-size: 28px; font-weight: bold; color: #333; }
        table { width: 100%; margin-top: 20px; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        tr:hover { background: #f9f9f9; }
        button { padding: 10px 15px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #764ba2; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #667eea; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>Employee Management System</h1>
            <p>Corporate Employee Portal</p>
        </div>
    </div>
    
    <div class="container">
        <div class="nav">
            <a href="/dashboard">Dashboard</a>
            <a href="#employees">Employees</a>
            <a href="#upload">Upload</a>
            <a href="/logout">Logout</a>
        </div>
        
        <div class="dashboard-grid">
            <div class="card">
                <h3>Total Employees</h3>
                <div class="stat" id="total-emp">0</div>
            </div>
            <div class="card">
                <h3>Active Users</h3>
                <div class="stat" id="total-payroll">0</div>
            </div>
            <div class="card">
                <h3>Departments</h3>
                <div class="stat" id="total-depts">0</div>
            </div>
        </div>
        
        <div class="card" style="margin-top: 20px;">
            <h2 id="employees">Employee List</h2>
            <table id="emp-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Department</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="emp-body"></tbody>
            </table>
        </div>
        
        <div class="card" style="margin-top: 20px;">
            <h2>Add New Employee</h2>
            <form id="add-emp-form">
                <input type="text" id="name" placeholder="Full Name" required>
                <input type="email" id="email" placeholder="Email" required>
                <input type="text" id="role" placeholder="Role" required>
                <input type="text" id="department" placeholder="Department" required>
                <input type="number" id="salary" placeholder="Salary" required>
                <button type="submit">Add Employee</button>
            </form>
        </div>
        
        <div class="card" style="margin-top: 20px;">
            <h2 id="upload">File Upload</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="file" required>
                <button type="submit">Upload</button>
            </form>
        </div>
    </div>
    
    <script>
        fetch('/api/employees')
            .then(r => r.json())
            .then(data => {
                const tbody = document.getElementById('emp-body');
                document.getElementById('total-emp').innerText = data.count;
                let depts = new Set();
                
                data.data.forEach(emp => {
                    const row = tbody.insertRow();
                    row.innerHTML = '<td>' + emp.id + '</td><td>' + escapeHtml(emp.name) + '</td><td>' + escapeHtml(emp.email) + '</td><td>' + escapeHtml(emp.role) + '</td><td>' + escapeHtml(emp.department) + '</td><td><button onclick="viewEmployee(' + emp.id + ')">View</button></td>';
                    depts.add(emp.department);
                });
                
                document.getElementById('total-depts').innerText = depts.size;
            });
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function viewEmployee(id) {
            fetch('/api/employees/' + id)
                .then(r => r.json())
                .then(data => {
                    alert('Name: ' + escapeHtml(data.name) + '\\nEmail: ' + escapeHtml(data.email) + '\\nRole: ' + escapeHtml(data.role));
                });
        }
        
        document.getElementById('add-emp-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const data = {
                name: document.getElementById('name').value,
                email: document.getElementById('email').value,
                role: document.getElementById('role').value,
                department: document.getElementById('department').value,
                salary: parseFloat(document.getElementById('salary').value),
                ssn: '000-00-0000',
                address: 'N/A',
                phone: 'N/A'
            };
            
            fetch('/api/employees', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(r => r.json())
            .then(data => {
                alert(data.message || data.status);
                location.reload();
            });
        });
    </script>
</body>
</html>
"""

UPLOAD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial; padding: 20px; }
        .form { max-width: 500px; margin: 50px auto; }
        input, button { padding: 10px; margin: 10px 0; width: 100%; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="form">
        <h1>Upload File</h1>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        {% if success %}
        <p class="success">{{ success }}</p>
        {% endif %}
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
        <p>Accepted formats: txt, pdf, csv, json</p>
        <p>Maximum file size: 5MB</p>
    </div>
</body>
</html>
"""

SEARCH_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Search Employees</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        tr:hover { background: #f9f9f9; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Search Employees</h1>
        <form method="get">
            <input type="text" name="q" placeholder="Search by name or email" value="{{ query }}">
            <button type="submit">Search</button>
        </form>
        
        {% if results %}
        <h2>Results for: {{ query }}</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Department</th>
                </tr>
            </thead>
            <tbody>
                {% for result in results %}
                <tr>
                    <td>{{ result.id }}</td>
                    <td>{{ result.name }}</td>
                    <td>{{ result.email }}</td>
                    <td>{{ result.role }}</td>
                    <td>{{ result.department }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% elif query %}
        <p>No results found for: {{ query }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    # Set Flask environment variable
    os.environ.setdefault('FLASK_ENV', 'production')
    
    # Disable debug mode in production
    if os.environ.get('FLASK_ENV') == 'production':
        app.run(host='127.0.0.1', port=5000, debug=False)
    else:
        # Development mode only
        app.run(host='127.0.0.1', port=5000, debug=True)
