from __future__ import annotations

import asyncio
import logging

from backend.celery_app import celery_app
from scanner.scan_manager.models import ScanStatus
from scanner.scan_manager.pipeline import ScanCancelledError, run_pipeline
from scanner.scan_manager.scan_modes import get_mode
from scanner.scan_manager.scan_service import (
    get_scan,
    store_asset_intelligence,
    store_attack_paths,
    store_attack_surface,
    store_discovery,
    store_findings,
    update_scan,
)

logger = logging.getLogger(__name__)


@celery_app.task(
    name="scanner.scan_manager.start_scan",
    bind=True,
    max_retries=0,
)
def start_scan(self, scan_id: str, target: str, mode: str = "standard") -> dict[str, object]:
    """
    Celery entrypoint for a full scan.

    Dispatches all pipeline stages sequentially using the internal async
    engine functions and records progress in Redis after every stage.
    """
    logger.info("scan=%s target=%s mode=%s starting", scan_id, target, mode)

    job = get_scan(scan_id)
    if job and job.status == ScanStatus.CANCELLED:
        logger.info("scan=%s cancelled before start", scan_id)
        return {
            "scan_id": scan_id,
            "target": target,
            "mode": mode,
            "findings": [],
            "discovery": {},
            "total_findings": 0,
            "status": ScanStatus.CANCELLED.value,
        }

    update_scan(scan_id, status=ScanStatus.RUNNING)

    try:
        config = get_mode(mode)
        result = asyncio.run(run_pipeline(scan_id, target, config))

        job = get_scan(scan_id)
        if job and job.status == ScanStatus.CANCELLED:
            logger.info("scan=%s cancelled during execution; skip completion write", scan_id)
            return {
                "scan_id": scan_id,
                "target": target,
                "mode": mode,
                "findings": [],
                "discovery": {},
                "total_findings": 0,
                "status": ScanStatus.CANCELLED.value,
            }

        update_scan(scan_id, status=ScanStatus.COMPLETED, progress=1.0)
        store_findings(scan_id, result.get("findings", []))
        store_discovery(scan_id, result.get("discovery", {}))
        if result.get("attack_surface"):
            store_attack_surface(scan_id, result["attack_surface"])
        if result.get("attack_paths"):
            store_attack_paths(scan_id, result["attack_paths"])
        if result.get("asset_intelligence"):
            store_asset_intelligence(scan_id, result["asset_intelligence"])

        # Auto-register domain
        try:
            from backend.api.routes.assets import register_domain_from_scan
            register_domain_from_scan(
                target=target,
                scan_id=scan_id,
                scan_mode=mode,
                discovery=result.get("discovery"),
                findings=result.get("findings"),
            )
        except Exception as _e:
            logger.warning("scan=%s domain registration failed: %s", scan_id, _e)

        logger.info("scan=%s completed findings=%d", scan_id, result.get("total_findings", 0))
        return result

    except ScanCancelledError:
        logger.info("scan=%s cancellation detected in pipeline", scan_id)
        update_scan(scan_id, status=ScanStatus.CANCELLED)
        return {
            "scan_id": scan_id,
            "target": target,
            "mode": mode,
            "findings": [],
            "discovery": {},
            "total_findings": 0,
            "status": ScanStatus.CANCELLED.value,
        }

    except Exception as exc:
        job = get_scan(scan_id)
        if job and job.status == ScanStatus.CANCELLED:
            logger.info("scan=%s cancelled; suppress fail status update", scan_id)
            return {
                "scan_id": scan_id,
                "target": target,
                "mode": mode,
                "findings": [],
                "discovery": {},
                "total_findings": 0,
                "status": ScanStatus.CANCELLED.value,
            }

        logger.exception("scan=%s failed: %s", scan_id, exc)
        update_scan(scan_id, status=ScanStatus.FAILED, error=str(exc))
        raise
