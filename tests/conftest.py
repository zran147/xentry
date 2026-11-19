"""Suite-wide guards.

REFUSING TO RUN AS ROOT IS NOT PEDANTRY HERE.

tests/test_url_approval.py executes targets/common/setup-generic.sh with bash.
That script is what runs *inside a guest VM*, as root, and it configures the
machine it runs on using absolute paths:

    mkdir -p /var/lib/xentry
    install -d -m 755 /etc/apt/sources.list.d /etc/apt/apt.conf.d
    : > /etc/apt/sources.list
    rm -f /etc/apt/sources.list.d/ubuntu.sources

Run the suite as an ordinary user and those fail with EACCES, the script exits,
and the test still makes its assertion. Run it under sudo and they SUCCEED --
against the host. That is not hypothetical: it emptied this host's
/etc/apt/sources.list and deleted its ubuntu.sources twice, on two different
days, because deployment scripts ran `pytest` under sudo as a pre-flight check.
apt then had no Ubuntu archive at all and every package reported "no
installation candidate".

The honest fix is for the suite to refuse the ambient authority rather than for
each test to remember it is dangerous.
"""
import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    if os.geteuid() == 0 and not os.environ.get("XENTRY_ALLOW_ROOT_TESTS"):
        raise pytest.UsageError(
            "refusing to run the test suite as root.\n"
            "Some tests execute targets/common/setup-generic.sh, which rewrites\n"
            "/etc/apt and /var/lib/xentry using absolute paths. As root those\n"
            "writes land on THIS host.\n"
            "Run it as an ordinary user:  .venv/bin/python -m pytest -q"
        )
