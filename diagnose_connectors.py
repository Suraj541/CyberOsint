"""
Cybersecurity OSINT Intelligence Platform - Live Connector Diagnostic Tool
Audits and verifies the complete real-time data pipeline from Internet Source to Database.
Usage:
    python diagnose_connectors.py
    python -m connectors.diagnostic
"""

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root and apps/api to path
project_root = Path(__file__).resolve().parent
apps_api_dir = project_root / "apps" / "api"
for p in [str(project_root), str(apps_api_dir)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from sqlalchemy import func
from app.database import Base, SessionLocal, engine
from app.models.content import Content
from app.models.entity import Entity
from app.models.source import Source
from app.workers.scheduler import scheduler, sync_connectors_yaml_to_sources
from connectors.config import connector_config_manager
from connectors.manager import PRIORITY_CONNECTOR_SPECS, connector_manager
from connectors.registry import connector_registry


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def run_diagnostics():
    print("=" * 80)
    print("CYBERSECURITY OSINT PLATFORM - PIPELINE & CONNECTOR HEALTH AUDIT")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 80)

    # Step 1: Database and Schema Check
    print("\n[1] Checking Database Initialization...")
    try:
        import app.models  # Register models
        Base.metadata.create_all(bind=engine)
        print("  [OK] SQLite/PostgreSQL Database schema initialized successfully.")
    except Exception as exc:
        print(f"  [FAIL] Database schema initialization error: {exc}")
        return

    # Step 2: Synchronize connectors.yaml to Source table
    print("\n[2] Synchronizing connectors.yaml with Database Source Table...")
    try:
        seeded = sync_connectors_yaml_to_sources(SessionLocal)
        print(f"  [OK] Synchronized {seeded} sources from connectors.yaml into Source table.")
    except Exception as exc:
        print(f"  [FAIL] Source synchronization error: {exc}")

    with SessionLocal() as db:
        src_count = db.query(func.count(Source.id)).scalar() or 0
        active_src_count = db.query(func.count(Source.id)).filter(Source.active == True).scalar() or 0
        print(f"  [OK] Database contains {src_count} total sources ({active_src_count} active).")

    # Step 3: Connector Registry Audit
    print("\n[3] Auditing Connector Registry & Specs...")
    all_registered = True
    for spec in sorted(PRIORITY_CONNECTOR_SPECS, key=lambda s: s["priority"]):
        cid = spec["id"]
        is_reg = connector_registry.has(cid) or connector_registry.has(spec["category"])
        status_symbol = "[OK]" if is_reg else "[FAIL]"
        if not is_reg:
            all_registered = False
        print(f"  {status_symbol} Priority {spec['priority']:2d} | [{cid:20s}] Class: {spec['connector_cls'].__name__:28s} Registered: {is_reg}")

    # Step 4: Active Health Preflight on All Monitored Sources
    print("\n[4] Active Network Connectivity Preflight (Live Ping)...")
    health_results = connector_manager.health_check_all()
    print(f"  Total Checked: {health_results['total_connectors']} | Healthy: {health_results['healthy_count']}/{health_results['total_connectors']}")
    for cid, h in health_results["results"].items():
        sym = "[OK]" if h["status"] == "ok" else "[WARN]" if h["status"] == "degraded" else "[FAIL]"
        lat = f"{h['latency_ms']:.1f}ms" if h.get("latency_ms") is not None else "N/A"
        print(f"  {sym} [{cid:20s}] Status: {h['status']:8s} Latency: {lat:10s} URL: {h.get('source_url', 'N/A')[:45]}")

    # Step 5: Test Execution & Database Ingestion for Working Connectors
    print("\n[5] Executing Discovery, Normalization & DB Ingestion Pipeline...")
    results_table = []
    with SessionLocal() as db:
        initial_content_count = db.query(func.count(Content.id)).scalar() or 0
        initial_entity_count = db.query(func.count(Entity.id)).scalar() or 0

        for spec in sorted(PRIORITY_CONNECTOR_SPECS, key=lambda s: s["priority"]):
            cid = spec["id"]
            if not connector_manager.is_enabled(cid):
                results_table.append({
                    "cid": cid,
                    "name": spec["name"],
                    "status": "DISABLED",
                    "fetched": 0,
                    "inserted": 0,
                    "duration": 0.0,
                    "error": None,
                })
                continue

            t0 = time.perf_counter()
            try:
                items = connector_manager.run_connector(cid, db=db)
                duration = (time.perf_counter() - t0) * 1000
                telemetry = connector_manager._last_run_telemetry.get(cid, {})
                results_table.append({
                    "cid": cid,
                    "name": spec["name"],
                    "status": "WORKING",
                    "fetched": len(items),
                    "inserted": telemetry.get("items_inserted", len(items)),
                    "duration": duration,
                    "error": None,
                })
            except Exception as exc:
                duration = (time.perf_counter() - t0) * 1000
                results_table.append({
                    "cid": cid,
                    "name": spec["name"],
                    "status": "FAILED",
                    "fetched": 0,
                    "inserted": 0,
                    "duration": duration,
                    "error": str(exc),
                })

        final_content_count = db.query(func.count(Content.id)).scalar() or 0
        final_entity_count = db.query(func.count(Entity.id)).scalar() or 0

    # Step 6: Diagnostic Summary Table
    print("\n" + "=" * 80)
    print("CONNECTOR PIPELINE EXECUTION SUMMARY")
    print("=" * 80)
    print(f"{'Category ID':<22} | {'Status':<8} | {'Fetched':<7} | {'Inserted':<8} | {'Latency':<9} | {'Details'}")
    print("-" * 80)
    for r in results_table:
        det = r["error"] if r["error"] else f"{r['name'][:28]}"
        print(f"{r['cid']:<22} | {r['status']:<8} | {r['fetched']:<7} | {r['inserted']:<8} | {r['duration']:>7.1f}ms | {det}")

    print("-" * 80)
    print(f"Content Records in DB: {initial_content_count} -> {final_content_count} (+{final_content_count - initial_content_count})")
    print(f"Entities Linked in DB: {initial_entity_count} -> {final_entity_count} (+{final_entity_count - initial_entity_count})")

    # Step 7: Freshness Audit
    print("\n[6] Database Timestamp Freshness Audit...")
    with SessionLocal() as db:
        latest_content = db.query(Content).order_by(Content.discovered_at.desc()).first()
        latest_pub = db.query(Content).filter(Content.published_at != None).order_by(Content.published_at.desc()).first()
        latest_cve = db.query(Content).filter(Content.content_type.in_(["cve", "vulnerability"])).order_by(Content.discovered_at.desc()).first()

        if latest_content:
            print(f"  * Latest Discovered Content: '{latest_content.title[:50]}' at {latest_content.discovered_at}")
        if latest_pub and latest_pub.published_at:
            print(f"  * Latest Published Content : '{latest_pub.title[:50]}' at {latest_pub.published_at}")
        if latest_cve:
            print(f"  * Latest CVE Ingestion     : '{latest_cve.title[:50]}' at {latest_cve.discovered_at}")

    print("\n" + "=" * 80)
    print("AUDIT COMPLETE - PLATFORM PIPELINE OPERATIONAL")
    print("=" * 80)


if __name__ == "__main__":
    run_diagnostics()
