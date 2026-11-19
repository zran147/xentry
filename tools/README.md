# tools

Developer diagnostics. Not part of the application: the app and the broker
never call anything here, and nothing here is needed to run a job.

They live outside `src/`, `broker/` and `scripts/` because those three are
what `tests/test_budget.py` counts against `LINE_CAP`. A diagnostic that
prints forty lines of context is worth its length, and it should not have to
compete for the budget with the code it diagnoses — the same reasoning that
puts `deploy/proxy-vm/` outside it.

Each of these exists because something failed in a way that was hard to see.

| | |
|---|---|
| `watch-session.py` | Polls a job and prints each step as it changes, plus the harness session feed. Submitting a job and reading `journalctl` tells you less, later. |
| `probe-guest-ssh.sh` | The guest has an address and the broker still cannot reach it. Walks lease, route, bridge port state, filter and handshake in that order, because the answer has been at a different layer each time. |
| `vm-net-report.sh` | Why the proxy VM cannot reach the internet. Read-only and bounded. |
| `vm-packet-report.sh` | Watches packets on the job bridges. Read-only. Useful when the firewall looks right and traffic still vanishes. |
| `preflight.py` | Does the dated archive actually carry the package at an affected version? No model call, no VM. Answers in seconds the question that otherwise fails four steps into a job. |
| `restart-and-verify.sh` | Restarts both services and proves the restart happened, by PID and by start time. An install script once placed its files and exited before its restart, and the running app was thirteen minutes old while every file on disk was correct. |

Two tools were deliberately not kept. `build-matrix-images.sh` duplicated
`scripts/build-images.sh`, which is maintained and tested, while hardcoding a
developer's home directory. `grant-dev-access.sh` is now `DEV=1` in
`install.sh`, which also validates its own sudoers rules — `visudo -cf` exits 0
on a rule that parses but grants nothing, so the exit status alone was never
enough.
