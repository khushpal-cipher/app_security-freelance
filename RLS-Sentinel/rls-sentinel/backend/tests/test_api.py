from fastapi.testclient import TestClient

import app.main as main_module

VALID_URL = "https://abcdefghijklmnop.supabase.co"


def _noop_run_scan(scan_id, target_url, anon_key, settings, table_names=None):
    """Stub scanner: marks the scan complete without any network I/O."""
    from sqlmodel import Session

    from app.db import engine
    from app.models import Scan, ScanStatus

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        scan.status = ScanStatus.COMPLETE
        scan.findings_count = 0
        session.add(scan)
        session.commit()


def test_scan_requires_authorized_true(monkeypatch):
    monkeypatch.setattr(main_module, "run_scan", _noop_run_scan)
    with TestClient(main_module.app) as client:
        resp = client.post(
            "/scan",
            json={
                "target_url": VALID_URL,
                "anon_key": "fake-anon-key",
                "authorized": False,
            },
        )
        assert resp.status_code == 422


def test_scan_rejects_non_supabase_host(monkeypatch):
    monkeypatch.setattr(main_module, "run_scan", _noop_run_scan)
    with TestClient(main_module.app) as client:
        resp = client.post(
            "/scan",
            json={
                "target_url": "https://evil.com",
                "anon_key": "fake-anon-key",
                "authorized": True,
            },
        )
        assert resp.status_code == 422


def test_scan_missing_anon_key_returns_422(monkeypatch):
    monkeypatch.setattr(main_module, "run_scan", _noop_run_scan)
    with TestClient(main_module.app) as client:
        resp = client.post(
            "/scan", json={"target_url": VALID_URL, "authorized": True}
        )
        assert resp.status_code == 422


def test_scan_happy_path_creates_scan_and_reports(monkeypatch):
    monkeypatch.setattr(main_module, "run_scan", _noop_run_scan)
    with TestClient(main_module.app) as client:
        create_resp = client.post(
            "/scan",
            json={
                "target_url": VALID_URL,
                "anon_key": "fake-anon-key",
                "authorized": True,
            },
        )
        assert create_resp.status_code == 202
        scan_id = create_resp.json()["scan_id"]
        assert scan_id

        status_resp = client.get(f"/scan/{scan_id}")
        assert status_resp.status_code == 200
        body = status_resp.json()
        assert body["status"] == "complete"
        assert body["findings"] == []

        report_resp = client.get(f"/scan/{scan_id}/report.json")
        assert report_resp.status_code == 200
        report = report_resp.json()
        assert report["scan_id"] == scan_id
        assert report["target_url"] == VALID_URL


def test_get_unknown_scan_returns_404(monkeypatch):
    monkeypatch.setattr(main_module, "run_scan", _noop_run_scan)
    with TestClient(main_module.app) as client:
        resp = client.get("/scan/does-not-exist")
        assert resp.status_code == 404


def test_health_endpoint():
    with TestClient(main_module.app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
