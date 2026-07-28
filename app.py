from flask import Flask, jsonify, request

app = Flask(__name__)

# In-memory database for demonstration
employees = [
    {"id": 1, "name": "Alice", "role": "Developer"},
    {"id": 2, "name": "Bob", "role": "DevOps Engineer"}
]

@app.route('/employees', methods=['GET'])
def get_employees():
    return jsonify(employees), 200

@app.route('/employees', methods=['POST'])
def add_employee():
    data = request.get_json()
    if not data or 'name' not in data or 'role' not in data:
        return jsonify({"error": "Invalid payload"}), 400
    
    new_emp = {
        "id": len(employees) + 1,
        "name": data['name'],
        "role": data['role']
    }
    employees.append(new_emp)
    return jsonify(new_emp), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
