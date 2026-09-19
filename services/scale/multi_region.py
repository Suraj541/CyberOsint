"""Section 49 (Step 48): Multi-Region Deployment & Geo-Routing Service.

Manages:
  - Multi-datacenter cluster topologies (us-east-1, eu-central-1, ap-southeast-1)
  - Active-Active / Active-Passive replication tracking and replication lag
  - Latency-aware geo-routing resolver
  - Disaster recovery failover simulation
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.scale import RegionNodeModel
from app.schemas.scale import FailoverRequest, GeoRouteRequest, GeoRouteResponse, RegionNodeOut

INITIAL_REGIONS = [
    {
        "region_code": "us-east-1",
        "name": "US East (N. Virginia)",
        "endpoint": "https://us-east.osint.corp.internal",
        "role": "primary",
        "status": "healthy",
        "latency_ms": 12.4,
        "replication_lag_ms": 0.0,
        "active_connections": 1420,
    },
    {
        "region_code": "eu-central-1",
        "name": "Europe (Frankfurt)",
        "endpoint": "https://eu-central.osint.corp.internal",
        "role": "replica",
        "status": "healthy",
        "latency_ms": 24.8,
        "replication_lag_ms": 3.2,
        "active_connections": 890,
    },
    {
        "region_code": "ap-southeast-1",
        "name": "Asia Pacific (Singapore)",
        "endpoint": "https://ap-southeast.osint.corp.internal",
        "role": "replica",
        "status": "healthy",
        "latency_ms": 48.1,
        "replication_lag_ms": 6.5,
        "active_connections": 610,
    },
]


def seed_regions(db: Session) -> None:
    """Seeds default regional clusters if none exist."""
    count = db.query(RegionNodeModel).count()
    if count > 0:
        return

    now = datetime.now(timezone.utc)
    for r in INITIAL_REGIONS:
        node = RegionNodeModel(
            region_code=r["region_code"],
            name=r["name"],
            endpoint=r["endpoint"],
            role=r["role"],
            status=r["status"],
            latency_ms=r["latency_ms"],
            replication_lag_ms=r["replication_lag_ms"],
            active_connections=r["active_connections"],
            last_heartbeat=now,
        )
        db.add(node)
    db.commit()


def list_region_nodes(db: Session) -> List[RegionNodeOut]:
    """Lists all regional deployment nodes and health metrics."""
    seed_regions(db)
    nodes = db.query(RegionNodeModel).all()
    return [_to_out(n) for n in nodes]


def resolve_geo_route(db: Session, req: GeoRouteRequest) -> GeoRouteResponse:
    """Resolves optimal regional datacenter based on client IP or preferred region."""
    seed_regions(db)
    nodes = db.query(RegionNodeModel).filter(RegionNodeModel.status == "healthy").all()
    if not nodes:
        nodes = db.query(RegionNodeModel).all()

    # If preferred region is supplied and healthy, honor it
    if req.preferred_region:
        match = next((n for n in nodes if n.region_code == req.preferred_region), None)
        if match:
            return GeoRouteResponse(
                routed_region=match.region_code,
                endpoint=match.endpoint,
                estimated_latency_ms=match.latency_ms,
                reason=f"Client preference honored for {match.region_code}",
            )

    # IP-based heuristic routing simulation
    ip = req.client_ip or "198.51.100.1"
    first_octet = int(ip.split(".")[0]) if ip and "." in ip else 198

    if first_octet < 100:
        selected_region = "eu-central-1"
    elif first_octet < 180:
        selected_region = "ap-southeast-1"
    else:
        selected_region = "us-east-1"

    node = next((n for n in nodes if n.region_code == selected_region), nodes[0])
    return GeoRouteResponse(
        routed_region=node.region_code,
        endpoint=node.endpoint,
        estimated_latency_ms=node.latency_ms,
        reason=f"Geo-IP proximity routing to nearest healthy cluster ({node.region_code})",
    )


def execute_failover(db: Session, req: FailoverRequest) -> List[RegionNodeOut]:
    """Simulates disaster recovery failover by promoting a replica to primary."""
    seed_regions(db)
    failed = db.query(RegionNodeModel).filter(RegionNodeModel.region_code == req.failed_region).first()
    target = db.query(RegionNodeModel).filter(RegionNodeModel.region_code == req.target_primary_region).first()

    if failed:
        failed.status = "offline"
        failed.role = "replica"
    if target:
        target.role = "primary"
        target.status = "healthy"
        target.replication_lag_ms = 0.0

    db.commit()
    return list_region_nodes(db)


def _to_out(node: RegionNodeModel) -> RegionNodeOut:
    return RegionNodeOut(
        id=node.id,
        region_code=node.region_code,
        name=node.name,
        endpoint=node.endpoint,
        role=node.role,
        status=node.status,
        latency_ms=node.latency_ms,
        replication_lag_ms=node.replication_lag_ms,
        active_connections=node.active_connections,
        last_heartbeat=node.last_heartbeat.isoformat() if node.last_heartbeat else "",
    )
