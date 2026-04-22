import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

app = FastAPI(title="wascan Dashboard")
templates = Jinja2Templates(Path(__file__).parent / "dashboard" / "templates")


class ScanProfile(str, BaseModel):
    QUICK = "quick"
    STEALTH = "stealth"
    FULL = "full"


class ScanCreate(BaseModel):
    target: str
    profile: Optional[str] = "full"
    spider_depth: Optional[int] = 2
    spider_pages: Optional[int] = 50


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: Optional[str] = ""
    url: Optional[str] = ""
    recommendation: Optional[str] = ""


class ScanResult(BaseModel):
    id: str
    target: str
    status: str
    started_at: str
    finished_at: Optional[str] = None
    findings: list = []
    crawled_urls: list = []
    discovered_subdomains: list = []


scans: dict = {}


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api")
async def api_root():
    return {"name": "wascan API", "version": "1.0.0"}


@app.get("/api/scans", response_model=list)
async def list_scans(limit: int = Query(50, le=100)):
    result = []
    for sid, scan in list(scans.items())[-limit:]:
        result.append({
            "id": sid,
            "target": scan["target"],
            "status": scan["status"],
            "started_at": scan["started_at"],
            "findings_count": len(scan.get("findings", [])),
        })
    return result


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@app.post("/api/scans", status_code=201)
async def create_scan(scan_data: ScanCreate, background_tasks: BackgroundTasks):
    import wascan as wascan_scanner

    scan_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    scans[scan_id] = {
        "id": scan_id,
        "target": scan_data.target,
        "status": "pending",
        "started_at": now,
        "findings": [],
        "crawled_urls": [],
        "discovered_subdomains": [],
    }

    async def run_scan_task():
        scans[scan_id]["status"] = "running"

        try:
            profile = scan_data.profile or "full"
            checks = wascan_scanner.SCAN_PROFILES.get(profile, [])

            result = await wascan_scanner.run_scan(
                target=scan_data.target,
                checks=checks if checks else None,
                spider_depth=scan_data.spider_depth,
                spider_pages=scan_data.spider_pages,
                subdomain_wordlist=wascan_scanner.SUBDOMAIN_WORDLIST,
                verbose=False,
            )

            scans[scan_id]["status"] = "completed"
            scans[scan_id]["finished_at"] = result.finished_at
            scans[scan_id]["findings"] = [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "url": f.url,
                    "recommendation": f.recommendation,
                }
                for f in result.sorted_findings()
            ]
            scans[scan_id]["crawled_urls"] = result.crawled_urls
            scans[scan_id]["discovered_subdomains"] = [
                {"name": s.name, "ip": s.ip, "status": s.status}
                for s in result.discovered_subdomains
            ]
        except Exception as e:
            scans[scan_id]["status"] = "failed"
            print(f"Scan failed: {e}")

    background_tasks.add_task(run_scan_task)
    return scans[scan_id]


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans[scan_id]
    return {"message": "Scan deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
