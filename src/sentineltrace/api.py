
"""SentinelTrace API: investigations, event explorer and evidence timeline."""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from sentineltrace.engine import analyze_events
from sentineltrace.parser import load_events
from sentineltrace.reporter import (
    build_report,
    write_markdown_report,
)
from sentineltrace.models import SecurityEvent


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVESTIGATIONS_DIR = PROJECT_ROOT / "data" / "investigations"
MAX_UPLOAD_SIZE = 25 * 1024 * 1024

INVESTIGATIONS_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="SentinelTrace API",
    description="Evidence-based SOC investigation platform",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def get_investigation_path(investigation_id: str) -> Path:
    if not investigation_id or Path(investigation_id).name != investigation_id:
        raise HTTPException(status_code=400, detail="Invalid investigation ID.")

    return INVESTIGATIONS_DIR / investigation_id


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Resource not found.") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Stored data is invalid.") from exc


def load_investigation(investigation_id: str):
    path = get_investigation_path(investigation_id) / "investigation.json"

    if not path.is_file():
        raise HTTPException(status_code=404, detail="Investigation not found.")

    return read_json(path)



def create_integrity_manifest(investigation_dir: Path) -> dict:
    """Create a SHA-256 manifest for saved investigation artifacts."""
    artifacts = {}

    for path in sorted(investigation_dir.iterdir()):
        if path.is_file() and path.name != "integrity.json":
            artifacts[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = {
        "algorithm": "SHA-256",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": artifacts,
    }

    (investigation_dir / "integrity.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return manifest


def verify_integrity_manifest(investigation_dir: Path) -> dict:
    """Compare current artifact hashes with the saved manifest."""
    manifest_path = investigation_dir / "integrity.json"

    if not manifest_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Integrity manifest not found. Re-upload this investigation.",
        )

    manifest = read_json(manifest_path)
    artifacts = manifest.get("artifacts")

    if not isinstance(artifacts, dict):
        raise HTTPException(status_code=500, detail="Integrity manifest is invalid.")

    results = {}
    for filename, expected_hash in artifacts.items():
        # Reject paths and filenames that could escape the investigation directory.
        if not isinstance(filename, str) or Path(filename).name != filename:
            results[str(filename)] = "invalid_manifest_entry"
            continue

        artifact_path = investigation_dir / filename
        if not artifact_path.is_file():
            results[filename] = "missing"
            continue

        actual_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        results[filename] = (
            "verified" if actual_hash == expected_hash else "mismatch"
        )

    verified = all(status == "verified" for status in results.values())

    return {
        "algorithm": manifest.get("algorithm", "unknown"),
        "verified": verified,
        "artifact_count": len(results),
        "results": results,
    }


def load_stored_events(investigation_id: str) -> list[dict]:
    path = get_investigation_path(investigation_id) / "events.json"

    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Event data is unavailable. Re-upload this log using the updated API.",
        )

    return read_json(path)


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SentinelTrace API",
        "version": "0.2.0",
    }


@app.post("/api/investigations", status_code=201)
async def create_investigation(file: UploadFile = File(...)):
    filename = Path(file.filename or "").name
    extension = Path(filename).suffix.lower()

    if extension not in {".json", ".jsonl"}:
        raise HTTPException(
            status_code=400,
            detail="Only JSON and JSONL files are supported.",
        )

    content = await file.read(MAX_UPLOAD_SIZE + 1)
    await file.close()

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="Upload exceeds 25 MB.")

    investigation_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    try:
        with TemporaryDirectory() as temp_dir:
            input_path = Path(temp_dir) / f"events{extension}"
            input_path.write_bytes(content)

            events, errors = load_events(input_path)
            findings = analyze_events(events)
            report = build_report(findings)

            normalized_events = [event.to_dict() for event in events]

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Unable to process uploaded logs: {exc}",
        ) from exc

    result = {
        "id": investigation_id,
        "created_at": created_at,
        "source_file": filename,
        "event_count": len(events),
        "rejected_count": len(errors),
        "finding_count": len(findings),
        "findings": report["findings"],
    }

    output_dir = INVESTIGATIONS_DIR / investigation_id
    output_dir.mkdir(parents=True, exist_ok=False)

    try:
        (output_dir / "investigation.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        (output_dir / "events.json").write_text(
            json.dumps(normalized_events, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        write_markdown_report(findings, output_dir)

        if errors:
            (output_dir / "parser_errors.json").write_text(
                json.dumps(errors, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        create_integrity_manifest(output_dir)

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not save investigation artifacts.",
        ) from exc

    return result


@app.get("/api/investigations")
def list_investigations():
    investigations = []

    for result_file in INVESTIGATIONS_DIR.glob("*/investigation.json"):
        try:
            data = read_json(result_file)
            investigations.append({
                "id": data["id"],
                "created_at": data["created_at"],
                "source_file": data["source_file"],
                "event_count": data["event_count"],
                "rejected_count": data["rejected_count"],
                "finding_count": data["finding_count"],
            })
        except (KeyError, HTTPException):
            continue

    investigations.sort(
        key=lambda item: item["created_at"],
        reverse=True,
    )
    return {"investigations": investigations}


@app.get("/api/investigations/{investigation_id}")
def get_investigation(investigation_id: str):
    return load_investigation(investigation_id)


@app.get("/api/investigations/{investigation_id}/events")
def get_events(
    investigation_id: str,
    search: str | None = None,
    event_id: str | None = None,
    host: str | None = None,
    severity: str | None = None,
    username: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    events = load_stored_events(investigation_id)

    if search:
        term = search.casefold()
        events = [
            event for event in events
            if term in json.dumps(event, ensure_ascii=False).casefold()
        ]

    if event_id:
        events = [e for e in events if e.get("event_id") == event_id]

    if host:
        events = [
            e for e in events
            if (e.get("host") or "").casefold() == host.casefold()
        ]

    if severity:
        events = [
            e for e in events
            if (e.get("severity") or "").casefold() == severity.casefold()
        ]

    if username:
        events = [
            e for e in events
            if username.casefold() in (e.get("username") or "").casefold()
        ]

    events.sort(key=lambda e: e.get("timestamp", ""))

    total = len(events)
    start = (page - 1) * page_size

    return {
        "investigation_id": investigation_id,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
        "events": events[start:start + page_size],
    }


@app.get("/api/investigations/{investigation_id}/timeline")
def get_timeline(
    investigation_id: str,
    limit: int = Query(500, ge=1, le=5000),
):
    events = load_stored_events(investigation_id)
    events.sort(key=lambda e: e.get("timestamp", ""))

    return {
        "investigation_id": investigation_id,
        "total_events": len(events),
        "returned_events": min(len(events), limit),
        "timeline": events[:limit],
    }


@app.get("/api/investigations/{investigation_id}/report")
def get_investigation_report(investigation_id: str):
    result = load_investigation(investigation_id)

    return {
        "report_name": "SentinelTrace SOC Investigation Report",
        "schema_version": "1.0",
        "investigation_id": result["id"],
        "created_at": result["created_at"],
        "event_count": result["event_count"],
        "rejected_count": result["rejected_count"],
        "finding_count": result["finding_count"],
        "findings": result["findings"],
    }


@app.get(
    "/api/investigations/{investigation_id}/report/markdown",
    response_class=PlainTextResponse,
)
def download_markdown_report(investigation_id: str):
    path = get_investigation_path(investigation_id) / "sentineltrace_report.md"

    if not path.is_file():
        raise HTTPException(status_code=404, detail="Markdown report not found.")

    return path.read_text(encoding="utf-8")


@app.get("/api/investigations/{investigation_id}/integrity")
def get_investigation_integrity(investigation_id: str):
    investigation_dir = get_investigation_path(investigation_id)
    if not (investigation_dir / "investigation.json").is_file():
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {
        "investigation_id": investigation_id,
        **verify_integrity_manifest(investigation_dir),
    }
