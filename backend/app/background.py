"""Asynchronous Investigation & Job Runner for SENTINEL.
Provides in-memory thread-safe background job scheduling and status tracking.
"""
import concurrent.futures
import logging
import threading
import time
import uuid
from typing import Any, Callable, Optional

logger = logging.getLogger("sentinel.background")

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="sentinel-worker")
_lock = threading.Lock()
_jobs: dict[str, dict] = {}


def submit_job(task_name: str, func: Callable, *args, **kwargs) -> str:
    """Submit a task to be processed asynchronously in the thread pool."""
    job_id = "job-" + uuid.uuid4().hex[:12]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    job_entry = {
        "job_id": job_id,
        "task_name": task_name,
        "status": "pending",
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "progress": 0.0,
        "result": None,
        "error": None
    }

    with _lock:
        _jobs[job_id] = job_entry
        _cleanup_old_jobs()

    def _runner():
        with _lock:
            if job_id in _jobs:
                _jobs[job_id]["status"] = "running"
                _jobs[job_id]["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                _jobs[job_id]["progress"] = 0.2

        try:
            res = func(*args, **kwargs)
            with _lock:
                if job_id in _jobs:
                    _jobs[job_id]["status"] = "completed"
                    _jobs[job_id]["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    _jobs[job_id]["progress"] = 1.0
                    _jobs[job_id]["result"] = res
        except Exception as e:
            logger.exception(f"Job {job_id} ({task_name}) failed: {e}")
            with _lock:
                if job_id in _jobs:
                    _jobs[job_id]["status"] = "failed"
                    _jobs[job_id]["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    _jobs[job_id]["error"] = str(e)

    _executor.submit(_runner)
    return job_id


def get_job(job_id: str) -> Optional[dict]:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return None
        return dict(job)


def _cleanup_old_jobs():
    """Keep memory bounded by removing jobs older than 1 hour."""
    now_ts = time.time()
    to_delete = []
    for jid, data in _jobs.items():
        if data["status"] in ("completed", "failed"):
            # check completed_at
            t_str = data.get("completed_at")
            if t_str:
                try:
                    c_ts = time.mktime(time.strptime(t_str, "%Y-%m-%dT%H:%M:%SZ"))
                    if now_ts - c_ts > 3600:
                        to_delete.append(jid)
                except Exception:
                    pass
    for jid in to_delete:
        del _jobs[jid]

