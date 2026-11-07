#!/usr/bin/env python3
"""Run one PHP2Shell job through the broker, runner, extractor, and validator."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import time
from pathlib import Path

from broker.main import BrokerServer
from broker.runtime import BrokerRuntime
from xentry.db import connect, init_db
from xentry.jobstore import get_job, list_steps, list_validations
from xentry.runner import JobRunner

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=ROOT / "var" / "smoke" / "php-job")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--keep-on-failure", action="store_true")
    parser.add_argument("--deadline", type=int, default=5400, help="job wait deadline in seconds")
    parser.add_argument("--qemu-user", default=os.environ.get("XENTRY_QEMU_USER", ""))
    parser.add_argument(
        "--cve-url",
        default=(
            "https://raw.githubusercontent.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit/"
            "167085410a9342fafbd1bd64f5006920dbc83b8e/README.md"
        ),
    )
    parser.add_argument(
        "--poc-url",
        default="https://github.com/78ResearchLab/PHP2Shell-Full-Chain-Exploit",
    )
    args = parser.parse_args()

    data_dir = args.data_dir
    if data_dir.exists():
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True)
    qemu_user = args.qemu_user
    if not qemu_user and os.getuid() != 0:
        qemu_user = pwd.getpwuid(os.getuid()).pw_name

    broker_data = data_dir / "broker"
    runtime = BrokerRuntime(
        broker_data,
        ROOT / "var" / "images",
        catalog_path=ROOT / "config" / "artifacts.yaml",
        apply_nft=False,
        qemu_user=qemu_user or None,
        manifest_path=ROOT / "var" / "artifacts" / "manifest.json",
        start_mirror=True,
        steps_manifest=ROOT / "targets" / "steps.yaml",
        targets_dir=ROOT / "targets",
    )
    socket_path = data_dir / "broker.sock"
    server = BrokerServer(
        socket_path,
        broker_data / "jobs",
        allowed_uids={os.getuid()},
        runtime=runtime,
    )
    server.start()

    db_path = data_dir / "app.db"
    init_db(db_path).close()
    runner = JobRunner(
        db_path=db_path,
        data_dir=data_dir / "app",
        broker_socket=socket_path,
        keep_on_failure=args.keep_on_failure,
        job_deadline_s=float(args.deadline),
    )
    runner.start()
    job_id = runner.submit(args.cve_url, args.poc_url)
    print("job", job_id, flush=True)
    deadline = time.monotonic() + args.deadline
    try:
        while time.monotonic() < deadline:
            conn = connect(db_path)
            try:
                job = get_job(conn, job_id)
            finally:
                conn.close()
            if job and job.get("outcome") is not None:
                break
            time.sleep(5)
        conn = connect(db_path)
        try:
            job = get_job(conn, job_id)
            steps = list_steps(conn, job_id)
            validations = list_validations(conn, job_id)
        finally:
            conn.close()
        print("job_record", json.dumps(job, indent=2, sort_keys=True, default=str), flush=True)
        print("steps", json.dumps(steps, indent=2, sort_keys=True, default=str), flush=True)
        print(
            "validations",
            json.dumps(validations, indent=2, sort_keys=True, default=str),
            flush=True,
        )
        return 0 if job and job.get("outcome") == "completed" else 1
    finally:
        runner.stop()
        server.stop()
        if not args.keep:
            # Keep the job database and attempt directory for inspection on failure.
            pass


if __name__ == "__main__":
    raise SystemExit(main())
