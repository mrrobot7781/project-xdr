import pytest
from app import app, DATABASE
import os

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for easier testing of POST/PUT requests
    with app.test_client() as client:
        yield client

def test_home_page(client):
    """Test the frontend UI route"""
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200

def test_get_employees_api(client):
    """Test the GET /api/employees endpoint"""
    response = client.get('/api/employees')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'success'
    assert len(json_data['data']) > 0

def test_login_and_logout(client):
    """Test login with credentials and subsequent logout"""
    # Test GET login page
    response = client.get('/login')
    assert response.status_code == 200

    # Test POST login with valid credentials
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'admin123'
    }, follow_redirects=True)
    assert response.status_code == 200

    # Test dashboard access after login
    response = client.get('/dashboard')
    assert response.status_code == 200

    # Test logout
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200

def test_get_employee_details(client):
    """Test IDOR employee endpoint"""
    response = client.get('/api/employees/101')
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == 'Akshay Kumar'

    # Test non-existent employee
    response = client.get('/api/employees/9999')
    assert response.status_code == 404

def test_search_endpoint(client):
    """Test search functionality"""
    response = client.get('/search?q=Akshay')
    assert response.status_code == 200

def test_system_info(client):
    """Test debug system info endpoint"""
    response = client.get('/api/debug/sql')
    assert response.status_code == 200
    data = response.get_json()
    assert 'db_host' in data

    response_sys = client.get('/api/system-info')
    assert response_sys.status_code == 200

def test_add_and_update_delete_employee(client):
    """Test adding, updating, and deleting an employee via API"""
    # Add employee
    new_emp = {
        'name': 'Test User',
        'email': 'test@corp.com',
        'role': 'Tester',
        'department': 'QA',
        'salary': 50000,
        'password': 'pass',
        'ssn': '111-11-1111',
        'address': 'Test Address',
        'phone': '1234567890'
    }
    res = client.post('/api/employees', json=new_emp)
    assert res.status_code == 201

    # Update employee (ID 101)
    update_data = {
        'name': 'Akshay Updated',
        'email': 'akshay.updated@corp.com',
        'salary': 130000
    }
    res_put = client.put('/api/employees/101', json=update_data)
    assert res_put.status_code == 200

    # Delete employee (ID 105)
    res_del = client.delete('/api/employees/105')
    assert res_del.status_code == 200

def test_performance_reviews(client):
    """Test adding and fetching performance reviews"""
    review_data = {
        'rating': 4.5,
        'comments': 'Great performance!'
    }
    res_post = client.post('/api/performance/101', json=review_data)
    assert res_post.status_code == 201

    res_get = client.get('/api/performance/101')
    assert res_get.status_code == 200

def test_export_data(client):
    """Test JSON and CSV exports"""
    res_json = client.post('/api/export?format=json')
    assert res_json.status_code == 200

    res_csv = client.post('/api/export?format=csv')
    assert res_csv.status_code == 200
    assert 'Content-Type' in res_csv.headers
