from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session
import asyncio
import logging

from app.database import get_db
from app.models.models import Sample

logger = logging.getLogger("cyberforge.api.sandbox")
router = APIRouter(prefix="/api/sandbox", tags=["Sandbox"])

@router.websocket("/live/{sample_id}")
async def live_sandbox_stream(websocket: WebSocket, sample_id: str, db: Session = Depends(get_db)):
    await websocket.accept()
    
    sample = db.query(Sample).filter(Sample.id == sample_id).first()
    if not sample or not sample.analysis_data:
        logger.warning(f"Live sandbox stream failed: sample {sample_id} not found or no analysis data")
        await websocket.close(code=1008)
        return

    dynamic = sample.analysis_data.get("dynamic_result")
    if not dynamic or not dynamic.get("events"):
        logger.warning(f"Live sandbox stream failed: sample {sample_id} has no dynamic events")
        await websocket.close(code=1008)
        return

    events = dynamic["events"]
    
    try:
        # Simulate VM Boot
        await websocket.send_json({"type": "status", "message": "Booting Windows VM snapshot..."})
        await asyncio.sleep(1.0)
        await websocket.send_json({"type": "status", "message": "VM Ready. Intercepting network traffic..."})
        await asyncio.sleep(0.5)
        await websocket.send_json({"type": "status", "message": f"Executing {sample.filename} in sandbox..."})
        await asyncio.sleep(0.5)

        current_time = 0
        for ev in events:
            delay = (ev["timestamp_ms"] - current_time) / 1000.0
            if delay > 0:
                # Compress time by 3x so a 90s simulation takes ~30s max for good UX
                sleep_time = min(delay * 0.33, 2.0) 
                await asyncio.sleep(sleep_time)
            
            await websocket.send_json({"type": "event", "data": ev})
            current_time = ev["timestamp_ms"]

        await asyncio.sleep(1.0)
        await websocket.send_json({"type": "status", "message": "Execution timeout reached. Collecting final artifacts..."})
        await asyncio.sleep(1.0)
        await websocket.send_json({"type": "done", "result": dynamic})
        await websocket.close(code=1000)
        
    except WebSocketDisconnect:
        logger.info(f"Client disconnected from live sandbox stream for {sample_id}")
    except Exception as e:
        logger.error(f"Error in live sandbox stream: {e}")
        try:
            await websocket.close(code=1011)
        except:
            pass
