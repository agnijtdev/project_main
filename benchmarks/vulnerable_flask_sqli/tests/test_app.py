import pytest
from app import app, init_db


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_get_existing_user(client):
    """Functional Feature Test: Valid user must return 200 with correct username."""
    response = client.get("/user?username=alice")
    assert response.status_code == 200
    data = response.get_json()
    assert data["username"] == "alice"
    assert data["role"] == "user"


def test_get_nonexistent_user(client):
    """Functional Feature Test: Non-existent user must return 404."""
    response = client.get("/user?username=nonexistent")
    assert response.status_code == 404


def test_missing_param(client):
    """Functional Feature Test: Missing parameter returns 400."""
    response = client.get("/user")
    assert response.status_code == 400
