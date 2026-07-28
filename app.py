from flask import Flask, jsonify, request, render_template_string

app = Flask(__name__)

# Sample In-Memory Database
employees = [
    {"id": 101, "name": "Akshay", "role": "DevSecOps Lead", "department": "Security Operations"},
    {"id": 102, "name": "Rohan", "role": "Cloud Architect", "department": "Infrastructure"},
    {"id": 103, "name": "Priya", "role": "Backend Engineer", "department": "Engineering"}
]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Portal | ASTRA-XDR Protected</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            margin: 0;
            padding: 40px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: #1e293b;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            border: 1px solid #334155;
        }
        h1 { color: #38bdf8; margin-top: 0; }
        .badge {
            background: rgba(56, 189, 248, 0.1);
            color: #38bdf8;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 25px;
        }
        th, td {
            text-align: left;
            padding: 12px 16px;
            border-bottom: 1px solid #334155;
        }
        th { background: #0f172a; color: #94a3b8; font-size: 12px; text-transform: uppercase; }
        tr:hover { background: #334155; }
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <h1>👥 Corporate Employee Management</h1>
            <span class="badge">🛡️ Protected by Falco eBPF</span>
        </div>
        <p style="color: #94a3b8;">Production Microservice Interface</p>
        
        <table>
            <thead>
                <tr>
                    <th>Emp ID</th>
                    <th>Full Name</th>
                    <th>Designation</th>
                    <th>Department</th>
                </tr>
            </thead>
            <tbody>
                {% for e in employees %}
                <tr>
                    <td><code>#{{ e.id }}</code></td>
                    <td><strong>{{ e.name }}</strong></td>
                    <td>{{ e.role }}</td>
                    <td>{{ e.department }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, employees=employees)

@app.route('/api/employees', methods=['GET'])
def get_employees():
    return jsonify({"status": "success", "data": employees}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
