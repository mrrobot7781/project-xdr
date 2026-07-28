import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_get_employees(client):
    response = client.get('/employees')
    assert response.status_code == 200
    assert len(response.get_json()) == 2

def test_add_employee(client):
    response = client.post('/employees', json={"name": "Charlie", "role": "Security Lead"})
    assert response.status_code == 201
    assert response.get_json()["name"] == "Charlie"
