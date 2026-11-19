"""Tail a job's steps and its harness session. Run: watch-session.py <job_id>"""

from __future__ import annotations

import http.client
import json
import sys
import time

HOST = "192.168.137.10"
PORT = 8000


def get(path: str, cookie: str) -> dict:
    conn = http.client.HTTPConnection(HOST, PORT, timeout=25)
    conn.request("GET", path, headers={"Host": "127.0.0.1", "Cookie": cookie})
    body = conn.getresponse().read()
    conn.close()
    try:
        return json.loads(body)
    except ValueError:
        return {}


def main() -> int:
    job = sys.argv[1]
    cookie = sys.argv[2]
    cursor = 0
    for _ in range(300):
        state = get(f"/api/jobs/{job}", cookie)
        steps = sorted(state.get("steps", []), key=lambda s: s["seq"])
        last = steps[-1] if steps else {}
        # NESTED UNDER "job". The payload is {"job": {...}, "steps": [...],
        # "validations": [...]} and `steps` is top level, so reading outcome
        # from the top level returns None forever - which is how the last
        # watcher polled a finished job for forty-five minutes.
        outcome = (state.get("job") or {}).get("outcome") or "running"
        print(
            f"{time.strftime('%H:%M:%S')}  {outcome:10} "
            f"seq{last.get('seq', 0):<3} {last.get('name', '-'):16} {last.get('state', '-')}",
            flush=True,
        )
        page = get(f"/api/jobs/{job}/session?cursor={cursor}", cookie)
        for item in page.get("items", []):
            kind = str(item.get("type", "")).replace("session_", "")
            body = item.get("payload", {})
            if kind == "tool_call":
                command = str(body.get("params", {}).get("command") or "")
                print(f"     -> {body.get('verb')}  {command[:100]}", flush=True)
            elif kind == "readiness":
                print(
                    f"     == readiness {body.get('reason_code')}: "
                    f"{str(body.get('detail') or '')[:200]}",
                    flush=True,
                )
            elif kind == "declaration":
                print(
                    f"     ** {body.get('declaration')} {body.get('reason_code')}: "
                    f"{str(body.get('summary') or '')[:300]}",
                    flush=True,
                )
            elif kind == "reasoning":
                print(f"     .. {str(body.get('text') or '')[:200]}", flush=True)
        cursor = int(page.get("cursor", cursor) or cursor)
        if outcome != "running":
            break
        time.sleep(20)

    final = get(f"/api/jobs/{job}", cookie)
    row = final.get("job") or {}
    print(f"\noutcome: {row.get('outcome')} | {row.get('reason_code')}")
    for step in sorted(final.get("steps", []), key=lambda s: s["seq"]):
        mark = "     " if step["state"] == "passed" else "FAIL "
        print(f"  {mark}seq{step['seq']:<3} {step['name']:16} {step['state']}")
        if step["state"] != "passed" and step.get("detail"):
            detail = str(step["detail"])[:1200].replace("\n", "\n        ")
            print(f"        {detail}")
    for row in final.get("validations", []):
        print(f"  validation: {row.get('verdict')} | {row.get('authority')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
