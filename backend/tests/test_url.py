from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_safe_url_returns_low_risk() -> None:
    response = client.post(
        "/api/analyze/url",
        json={
            "url": "https://google.com",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_level"] == "Low"
    assert data["signals"]["uses_https"] is True
    assert data["signals"]["domain"] == "google.com"


def test_suspicious_url_detects_warning_signals() -> None:
    response = client.post(
        "/api/analyze/url",
        json={
            "url": (
                "http://secure.paypa1-login.example.com/"
                "verify-account"
            ),
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] > 0
    assert data["signals"]["uses_https"] is False
    assert len(
        data["signals"]["suspicious_keywords"]
    ) > 0


def test_ip_address_url_is_detected() -> None:
    response = client.post(
        "/api/analyze/url",
        json={
            "url": "http://192.168.1.10/login",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["signals"]["contains_ip_address"]
        is True
    )


def test_empty_url_is_rejected() -> None:
    response = client.post(
        "/api/analyze/url",
        json={
            "url": "",
        },
    )

    assert response.status_code == 422