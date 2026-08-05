import pytest
from app import app, DATABASE
import os
import io

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        yield client

def test_home_page(client):
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200

def test_get_employees_api(client):
    response = client.get('/api/employees')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'success'
    assert len(json_data['data']) > 0

def test_login_and_logout(client):
    response = client.get('/login')
    assert response.status_code == 200

    # Successful login
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'admin123'
    }, follow_redirects=True)
    assert response.status_code == 200

    # Failed login (hits exception/error disclosure block)
    response = client.post('/login', data={
        'username': "admin' OR '1'='1",
        'password': 'wrong'
    }, follow_redirects=True)
    assert response.status_code == 200

    response = client.get('/dashboard')
    assert response.status_code == 200

    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200

def test_get_employee_details(client):
    response = client.get('/api/employees/101')
    assert response.status_code == 200
    data = response.get_json()
    assert data['name'] == 'Akshay Kumar'

    response = client.get('/api/employees/9999')
    assert response.status_code == 404

def test_search_endpoint(client):
    response = client.get('/search?q=Akshay')
    assert response.status_code == 200

def test_system_info(client):
    response = client.get('/api/debug/sql')
    assert response.status_code == 200

    response_sys = client.get('/api/system-info')
    assert response_sys.status_code == 200

def test_add_and_update_delete_employee(client):
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

    # Test adding employee with empty JSON payload
    res_err = client.post('/api/employees', json={})
    assert res_err.status_code == 201

    update_data = {
        'name': 'Akshay Updated',
        'email': 'akshay.updated@corp.com',
        'salary': 130000
    }
    res_put = client.put('/api/employees/101', json=update_data)
    assert res_put.status_code == 200

    res_del = client.delete('/api/employees/105')
    assert res_del.status_code == 200

def test_employee_update_errors(client):
    """Test PUT and DELETE error handling blocks"""
    client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    
    # Test PUT with bad data/syntax to trigger except block
    res_put = client.put('/api/employees/101', json={'name': None, 'email': None, 'salary': 'invalid_number'})
    assert res_put.status_code in [200, 400]

def test_performance_reviews(client):
    review_data = {
        'rating': 4.5,
        'comments': 'Great performance!'
    }
    res_post = client.post('/api/performance/101', json=review_data)
    assert res_post.status_code == 201

    res_get = client.get('/api/performance/101')
    assert res_get.status_code == 200

def test_export_data(client):
    res_json = client.post('/api/export?format=json')
    assert res_json.status_code == 200

    res_csv = client.post('/api/export?format=csv')
    assert res_csv.status_code == 200

def test_file_upload(client):
    """Test file upload endpoint (GET and POST)"""
    client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    
    res_get = client.get('/upload')
    assert res_get.status_code == 200

    data = {'file': (io.BytesIO(b"test file content"), 'test.txt')}
    res_post = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res_post.status_code == 200

def test_upload_missing_file_key(client):
    """Test file upload error when 'file' key is absent"""
    client.post('/login', data={'username': 'admin', 'password': 'admin123'}, follow_redirects=True)
    res = client.post('/upload', data={}, content_type='multipart/form-data')
    assert res.status_code in [200, 302, 400]

def test_import_xml(client):
    """Test XML import/XXE endpoint"""
    xml_data = "<root><data>test</data></root>"
    data = {'xml_file': (io.BytesIO(xml_data.encode('utf-8')), 'test.xml')}
    res = client.post('/api/import-xml', data=data, content_type='multipart/form-data')
    assert res.status_code == 200

    res_err = client.post('/api/import-xml', data={})
    assert res_err.status_code == 400

def test_export_pickle(client):
    """Test insecure deserialization pickle export endpoint"""
    res = client.get('/api/export-pickle')
    assert res.status_code == 200
