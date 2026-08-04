"""
Professional Employee Management Application
With intentional OWASP vulnerabilities for security testing
"""
import json
import pickle
import base64
import sqlite3
from functools import wraps
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from flask import Flask, jsonify, request, render_template_string, redirect, session, send_file
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

# FIX FOR PYTEST: Added root route '/' to resolve 404 error during CI/CD testing
@app.route('/')
def home():
    return render_template_string(LOGIN_TEMPLATE)
# VULNERABILITY #1: Hardcoded Secret Key (Information Disclosure + Weak Session Management)
app.secret_key = 'super-secret-key-12345-production'

# VULNERABILITY #2: Hardcoded Credentials in code
ADMIN_CREDENTIALS = {
    'username': 'admin',
    'password': 'admin123'  # Weak password
}

# Database setup with vulnerabilities
DATABASE = '/tmp/employee_app.db'
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'xml', 'json', 'csv', 'exe', 'sh'}  # VULNERABILITY: Dangerous file types allowed

def init_db():
    """Initialize database with sample data"""
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        # Create tables
        c.execute('''CREATE TABLE employees (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT,
            role TEXT,
            department TEXT,
            salary REAL,
            password TEXT,
            ssn TEXT,
            address TEXT,
            phone TEXT
        )''')
        
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT
        )''')
        
        c.execute('''CREATE TABLE performance (
            id INTEGER PRIMARY KEY,
            employee_id INTEGER,
            rating REAL,
            comments TEXT,
            date TEXT
        )''')
        
        # Insert sample data
        employees_data = [
            (101, 'Akshay Kumar', 'akshay@corp.com', 'DevSecOps Lead', 'Security Operations', 120000, 'pass123', '123-45-6789', '123 Main St', '555-0101'),
            (102, 'Rohan Singh', 'rohan@corp.com', 'Cloud Architect', 'Infrastructure', 110000, 'rohan@123', '234-56-7890', '456 Oak Ave', '555-0102'),
            (103, 'Priya Sharma', 'priya@corp.com', 'Backend Engineer', 'Engineering', 95000, 'priya#456', '345-67-8901', '789 Pine Rd', '555-0103'),
            (104, 'Vikram Patel', 'vikram@corp.com', 'Database Admin', 'Infrastructure', 105000, 'vikram@789', '456-78-9012', '101 Elm St', '555-0104'),
            (105, 'Neha Gupta', 'neha@corp.com', 'Security Engineer', 'Security Operations', 98000, 'neha!234', '567-89-0123', '202 Maple Dr', '555-0105'),
        ]
        
        c.executemany('INSERT INTO employees VALUES (?,?,?,?,?,?,?,?,?,?)', employees_data)
        
        users_data = [
            (1, 'admin', 'admin123', 'admin@corp.com', 'admin'),
            (2, 'manager', 'manager123', 'manager@corp.com', 'manager'),
            (3, 'user', 'user123', 'user@corp.com', 'user'),
        ]
        
        c.executemany('INSERT INTO users VALUES (?,?,?,?,?)', users_data)
        
        conn.commit()
        conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# VULNERABILITY #3: Weak Authentication check (No proper validation)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# VULNERABILITY #4: No CSRF Protection
# VULNERABILITY #5: No Rate Limiting
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # VULNERABILITY #6: Direct SQL Injection in authentication
        conn = get_db_connection()
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"  # SQL INJECTION!
        
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect('/dashboard')
            else:
                return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
        except Exception as e:
            conn.close()
            return render_template_string(LOGIN_TEMPLATE, error=f"Error: {str(e)}")  # VULNERABILITY: Error disclosure
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# VULNERABILITY #7: Insecure Direct Object Reference (IDOR)
@app.route('/api/employees/<int:emp_id>')
def get_employee_details(emp_id):
    """Get employee details - VULNERABLE to IDOR"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # No authorization check - direct ID access
    c.execute('SELECT * FROM employees WHERE id = ?', (emp_id,))
    employee = c.fetchone()
    conn.close()
    
    if employee:
        # VULNERABILITY #8: Sensitive data exposure (SSN, password, address exposed in API)
        return jsonify({
            'id': employee['id'],
            'name': employee['name'],
            'email': employee['email'],
            'role': employee['role'],
            'salary': employee['salary'],  # Sensitive!
            'ssn': employee['ssn'],  # PII exposure!
            'password': employee['password'],  # Credential exposure!
            'address': employee['address'],  # PII!
            'phone': employee['phone']
        })
    
    return jsonify({'error': 'Employee not found'}), 404

# VULNERABILITY #9: Reflected XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')  # No sanitization
    search_term = f"%{query}%"
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # VULNERABILITY #10: SQL Injection in search
    sql = f"SELECT * FROM employees WHERE name LIKE '{search_term}' OR email LIKE '{search_term}'"
    c.execute(sql)
    results = c.fetchall()
    conn.close()
    
    html = f"""
    <html>
    <body>
    <h2>Search Results for: {query}</h2>  <!-- XSS Vulnerability -->
    <table>
    """
    
    for emp in results:
        html += f"<tr><td>{emp['name']}</td><td>{emp['email']}</td></tr>"
    
    html += "</table></body></html>"
    return html, 200, {'Content-Type': 'text/html'}

# VULNERABILITY #11: Insecure File Upload
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file provided'
        
        file = request.files['file']
        
        if file.filename == '':
            return 'No file selected'
        
        # VULNERABILITY #12: No file type validation despite extension check
        # VULNERABILITY #13: Predictable file path
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        return f'File {filename} uploaded successfully to {filepath}'
    
    return render_template_string(UPLOAD_TEMPLATE)

# VULNERABILITY #14: XXE (XML External Entity) Vulnerability
@app.route('/api/import-xml', methods=['POST'])
def import_xml():
    if 'xml_file' not in request.files:
        return jsonify({'error': 'No XML file provided'}), 400
    
    xml_file = request.files['xml_file']
    xml_content = xml_file.read().decode('utf-8')
    
    try:
        # VULNERABILITY: XXE Attack - No security settings
        root = ET.fromstring(xml_content)
        
        return jsonify({
            'status': 'imported',
            'data': ET.tostring(root, encoding='unicode')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULNERABILITY #15: Insecure Deserialization
@app.route('/api/export-pickle', methods=['GET'])
def export_pickle():
    """Export employee data as pickle - Insecure Deserialization"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM employees')
    employees = c.fetchall()
    conn.close()
    
    emp_list = [dict(emp) for emp in employees]
    pickled = pickle.dumps(emp_list)
    encoded = base64.b64encode(pickled).decode()
    
    return jsonify({'data': encoded, 'format': 'pickle', 'warning': 'Use pickle.loads to deserialize'})

# VULNERABILITY #16: Debug mode and verbose error messages
@app.route('/api/debug/sql')
def debug_sql():
    """Debug endpoint exposing SQL queries"""
    return jsonify({
        'last_query': 'SELECT * FROM employees WHERE id = 1',
        'db_host': 'localhost',
        'db_user': 'admin',
        'db_password': 'dbpassword123'  # Credentials exposed!
    })

# VULNERABILITY #17: Missing Security Headers (app.py itself doesn't set them)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/api/employees', methods=['GET'])
def get_employees():
    """Get all employees - no authorization check"""
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

# VULNERABILITY #18: Broken Access Control - No role-based access
@app.route('/api/employees', methods=['POST'])
def add_employee():
    """Add employee - no authorization check"""
    data = request.get_json()
    
    # VULNERABILITY #19: No input validation on server side
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        c.execute('''INSERT INTO employees 
                    (name, email, role, department, salary, password, ssn, address, phone)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (data.get('name'), data.get('email'), data.get('role'),
                  data.get('department'), data.get('salary'), data.get('password'),
                  data.get('ssn'), data.get('address'), data.get('phone')))
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'message': 'Employee added'}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 400

# VULNERABILITY #20: Unsafe HTTP Methods
@app.route('/api/employees/<int:emp_id>', methods=['PUT', 'DELETE'])
def update_delete_employee(emp_id):
    """Update or delete employee - no CSRF protection"""
    
    if request.method == 'PUT':
        data = request.get_json()
        conn = get_db_connection()
        c = conn.cursor()
        
        update_query = f"""UPDATE employees SET 
                          name='{data.get('name')}',
                          email='{data.get('email')}',
                          salary={data.get('salary')}
                          WHERE id={emp_id}"""  # SQL INJECTION!
        
        try:
            c.execute(update_query)
            conn.commit()
            conn.close()
            return jsonify({'status': 'updated'})
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e)}), 400
    
    elif request.method == 'DELETE':
        conn = get_db_connection()
        c = conn.cursor()
        c.execute(f'DELETE FROM employees WHERE id = {emp_id}')  # SQL INJECTION!
        conn.commit()
        conn.close()
        return jsonify({'status': 'deleted'})

# VULNERABILITY #21: Performance ratings with stored XSS potential
@app.route('/api/performance/<int:emp_id>', methods=['POST'])
def add_performance(emp_id):
    """Add performance review - Stored XSS vulnerability"""
    data = request.get_json()
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # VULNERABILITY #22: No input sanitization for comments (Stored XSS)
    c.execute('''INSERT INTO performance (employee_id, rating, comments, date)
                 VALUES (?, ?, ?, ?)''',
             (emp_id, data.get('rating'), data.get('comments'), datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'review added'}), 201

@app.route('/api/performance/<int:emp_id>')
def get_performance(emp_id):
    """Get performance reviews - Returns unsanitized comments"""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('SELECT * FROM performance WHERE employee_id = ?', (emp_id,))
    reviews = c.fetchall()
    conn.close()
    
    # VULNERABILITY: Comments not escaped - XSS when rendered
    return jsonify({
        'employee_id': emp_id,
        'reviews': [dict(r) for r in reviews]
    })

# VULNERABILITY #23: Information Disclosure via comments
@app.route('/api/system-info')
def system_info():
    """Endpoint exposing system information"""
    return jsonify({
        'app_version': '1.0.0',
        'python_version': '3.9.0',
        'flask_version': '3.0.0',
        'database': DATABASE,
        'upload_folder': UPLOAD_FOLDER,
        'debug_mode': app.debug
    })

# VULNERABILITY #24: Missing Content-Type validation
@app.route('/api/export', methods=['POST'])
def export_data():
    """Export employee data in any format"""
    format_type = request.args.get('format', 'json')
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('SELECT * FROM employees')
    employees = c.fetchall()
    conn.close()
    
    data = [dict(emp) for emp in employees]
    
    if format_type == 'json':
        return jsonify(data)
    elif format_type == 'csv':
        # VULNERABILITY #25: CSV Injection
        csv_content = "ID,Name,Email,Role,Department,Salary,SSN\n"
        for emp in data:
            csv_content += f"{emp['id']},='{emp['name']}',{emp['email']},{emp['role']},{emp['department']},{emp['salary']},{emp['ssn']}\n"
        return csv_content, 200, {'Content-Type': 'text/csv'}

# Initialize database when app starts
init_db()

# Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Portal Login</title>
    <style>
        body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               margin: 0; padding: 0; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .login-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                          width: 300px; }
        h1 { color: #333; margin-top: 0; text-align: center; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #764ba2; }
        .error { color: red; text-align: center; }
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
            Demo: admin/admin123<br>manager/manager123<br>user/user123
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
                    row.innerHTML = '<td>' + emp.id + '</td><td>' + emp.name + '</td><td>' + emp.email + '</td><td>' + emp.role + '</td><td>' + emp.department + '</td><td><button onclick="viewEmployee(' + emp.id + ')">View</button></td>';
                    depts.add(emp.department);
                });
                
                document.getElementById('total-depts').innerText = depts.size;
            });
        
        function viewEmployee(id) {
            fetch('/api/employees/' + id)
                .then(r => r.json())
                .then(data => {
                    alert('Name: ' + data.name + '\\nEmail: ' + data.email + '\\nRole: ' + data.role);
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
                password: 'temp123',
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
    <style>
        body { font-family: Arial; padding: 20px; }
        .form { max-width: 500px; margin: 50px auto; }
        input, button { padding: 10px; margin: 10px 0; width: 100%; }
    </style>
</head>
<body>
    <div class="form">
        <h1>Upload File</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
        <p>Accepted formats: txt, pdf, xml, json, csv, exe, sh</p>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    # VULNERABILITY #26: Debug mode enabled in production
    app.run(host='0.0.0.0', port=5000, debug=True)
