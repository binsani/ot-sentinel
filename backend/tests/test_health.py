from fastapi.testclient import TestClient

from app.inventory import router as inventory_router
from app.main import app


def test_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"


def test_communication_graph_route_precedes_asset_uuid_route() -> None:
    paths = [route.path for route in inventory_router.routes]
    assert paths.index("/api/v1/assets/graph/communications") < paths.index(
        "/api/v1/assets/{asset_id}"
    )
