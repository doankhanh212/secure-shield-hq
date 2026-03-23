from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool

from scanner.scan_manager.scan_service import get_scan

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    try:
        while True:
            job = await run_in_threadpool(get_scan, scan_id)
            if not job:
                await websocket.send_json({"error": "scan not found"})
                break

            data = job.to_dict()
            await websocket.send_json(data)

            if job.status.value in ("completed", "failed", "cancelled"):
                break

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
