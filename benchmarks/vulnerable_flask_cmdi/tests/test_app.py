import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_missing_host(client):
    """Functional Feature Test: Missing host parameter returns 400."""
    response = client.get("/ping")
    assert response.status_code == 400


def test_ping_valid_host(client):
    """Functional Feature Test: Pinging localhost returns status success."""
    response = client.get("/ping?host=127.0.0.1")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
