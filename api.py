import asyncio
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, HttpUrl

app = FastAPI(
    title="wascan API",
    description="REST API for the wascan vulnerability scanner",
    version="1.0.0",
)


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanProfile(str, Enum):
    QUICK = "quick"
    STEALTH = "stealth"
    FULL = "full"


class ScanCreate(BaseModel):
    target: str
    profile: Optional[ScanProfile] = None
    checks: Optional[list[str]] = None
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
    status: ScanStatus
    started_at: str
    finished_at: Optional[str] = None
    findings: list[Finding] = []
    crawled_urls: list[str] = []
    discovered_subdomains: list[dict] = []


class ScanSummary(BaseModel):
    id: str
    target: str
    status: ScanStatus
    started_at: str
    findings_count: int


scans: dict[str, ScanResult] = {}


@app.get("/")
async def root():
    return {
        "name": "wascan API",
        "version": "1.0.0",
        "docs": "/docs",
    }


@app.get("/scans", response_model=list[ScanSummary])
async def list_scans(limit: int = Query(50, le=100)):
    return [
        ScanSummary(
            id=sid,
            target=scan.target,
            status=scan.status,
            started_at=scan.started_at,
            findings_count=len(scan.findings),
        )
        for sid, scan in list(scans.items())[-limit:]
    ]


@app.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@app.post("/scans", response_model=ScanResult, status_code=201)
async def create_scan(scan_data: ScanCreate, background_tasks: BackgroundTasks):
    import wascan as wascan_scanner

    scan_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    scans[scan_id] = ScanResult(
        id=scan_id,
        target=scan_data.target,
        status=ScanStatus.PENDING,
        started_at=now,
    )

    async def run_scan_task():
        scans[scan_id].status = ScanStatus.RUNNING

        try:
            result = await wascan_scanner.run_scan(
                target=scan_data.target,
                checks=scan_data.checks or [],
                spider_depth=scan_data.spider_depth,
                spider_pages=scan_data.spider_pages,
                subdomain_wordlist=wascan_scanner.SUBDOMAIN_WORDLIST,
                verbose=False,
            )

            scans[scan_id].status = ScanStatus.COMPLETED
            scans[scan_id].finished_at = result.finished_at
            scans[scan_id].findings = [
                Finding(
                    title=f.title,
                    severity=f.severity,
                    description=f.description,
                    evidence=f.evidence,
                    url=f.url,
                    recommendation=f.recommendation,
                )
                for f in result.sorted_findings()
            ]
            scans[scan_id].crawled_urls = result.crawled_urls
            scans[scan_id].discovered_subdomains = [
                {"name": s.name, "ip": s.ip, "status": s.status}
                for s in result.discovered_subdomains
            ]
        except Exception as e:
            scans[scan_id].status = ScanStatus.FAILED

    background_tasks.add_task(run_scan_task)
    return scans[scan_id]


@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans[scan_id]
    return {"message": "Scan deleted"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
