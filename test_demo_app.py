import pytest
from demo_app import app, init_db


@pytest.fixture
def client():
    init_db()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "healthy"
