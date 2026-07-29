import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page(client):
    """Test the frontend UI route"""
    response = client.get('/', follow_redirects=True)  # Added follow_redirects=True
    assert response.status_code == 200

def test_get_employees_api(client):
    """Test the GET /api/employees endpoint"""
    response = client.get('/api/employees')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['status'] == 'success'
    assert len(json_data['data']) > 0
