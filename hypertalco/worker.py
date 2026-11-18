import logging
import threading
import time


def process_one(store, agent):
    job = store.claim()
    if not job:
        return False
    try:
        result = agent.call(job["operation"], {**job["payload"], "job_id": job["id"]}, timeout=7200)
        store.finish(job["id"], result=result)
        store.audit(job["actor"], "job.succeeded", job["id"])
    except Exception as error:
        # Agent messages are sanitized; never include the queue payload in logs.
        store.finish(job["id"], error=str(error)[:1000])
        store.audit(job["actor"], "job.failed", job["id"])
        logging.warning("Job %s failed", job["id"])
    return True


def run_worker(store, agent, stop=None):
    stop = stop or threading.Event()
    store.recover_jobs()
    while not stop.is_set():
        if not process_one(store, agent):
            stop.wait(0.5)
