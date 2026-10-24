# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Remediation adapters: the ONLY module that changes the running demo.

Imported exclusively by action_api.py and only called AFTER a human approved the exact plan
(digest-bound, single-use, kill switch off). The investigation tools (agent.py, registry.py,
ops_tools.py, jaeger_tools.py, metrics.py) never import this module; tests/test_offline.py enforces that.

Swap this file if the organisers' starter kit ships a real Action API: action_api.py is the only caller
and only needs the four functions below.

Config (env): DEMO_DIR, COMPOSE_ARGS, FLAG_FILE, LOCUST_API_URL
"""
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import requests

def _docker_bin():
    """docker on PATH, or Docker Desktop's default location when a shell hides it from Python."""
    found = os.environ.get("DOCKER_BIN") or shutil.which("docker")
    default = Path(r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")
    return found or (str(default) if default.exists() else "docker")


DOCKER = _docker_bin()

AGENT_DIR = Path(__file__).resolve().parent
DEMO_DIR = Path(os.environ.get("DEMO_DIR", str(AGENT_DIR.parent))).expanduser().resolve()
COMPOSE = [DOCKER, "compose"] + shlex.split(os.environ.get("COMPOSE_ARGS", ""))
FLAG_FILE = Path(os.environ.get("FLAG_FILE", str(DEMO_DIR / "src" / "flagd" / "demo.flagd.json")))
LOCUST_API = os.environ.get("LOCUST_API_URL", "http://localhost:8080/loadgen").rstrip("/")


def _compose(*args, timeout=180):
    p = subprocess.run(COMPOSE + list(args), cwd=str(DEMO_DIR), capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip()[-300:])
    return p.stdout


def _is_running(service):
    try:
        cid = _compose("ps", "-q", service).strip().splitlines()
        if not cid:
            return False
        out = subprocess.run(
            [DOCKER, "inspect", "-f", "{{.State.Running}}", cid[0]],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip()
        return out == "true"
    except Exception:  # noqa: BLE001 - assume running, restart is the safe path
        return True


# ------------------------------------------------------------------ the four allowlisted actions
def restart_service(service, reset_limits=False):
    """Start a stopped container, or restart a running one. reset_limits recreates it (clears CPU/mem limits)."""
    if reset_limits:
        _compose("up", "-d", "--force-recreate", "--no-deps", service)
        return f"Recreated {service} with default resource limits"
    if not _is_running(service):
        _compose("up", "-d", "--no-deps", service)
        return f"Started stopped service {service}"
    _compose("restart", service)
    return f"Restarted service {service}"


def set_flag(flag_name, variant):
    """Set a remediation flag to `variant`. Returns the previous variant (for rollback).

    Edits the flag file the flag service watches, then restarts that service so the change is picked up.
    Flag names are matched case-insensitively against the file so a casing difference cannot break a fix.
    """
    data = json.loads(FLAG_FILE.read_text(encoding="utf-8"))
    flags = data.get("flags", {})
    actual = next((k for k in flags if k.lower() == flag_name.lower()), None)
    if actual is None:
        raise ValueError(f"flag {flag_name!r} does not exist in the flag file")
    if variant not in flags[actual].get("variants", {}):
        raise ValueError(f"flag {actual!r} has no variant {variant!r}")
    previous = flags[actual].get("defaultVariant")
    if previous != variant:
        flags[actual]["defaultVariant"] = variant
        # Written in place; the switch service notices the change itself within a second. Restarting it would
        # make every service throw connection errors and muddy the recovery check.
        FLAG_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return previous


def throttle_load(user_count, spawn_rate):
    """Reduce synthetic load via the Locust web API. Returns the previous user count (for rollback)."""
    previous = None
    try:
        previous = requests.get(f"{LOCUST_API}/stats/requests", timeout=5).json().get("user_count")
    except Exception:  # noqa: BLE001
        pass
    r = requests.post(f"{LOCUST_API}/swarm", data={"user_count": user_count, "spawn_rate": spawn_rate}, timeout=10)
    r.raise_for_status()
    return previous


def scale_service(service, replicas):
    """Docker Compose has no autoscaler; replicas>1 of published-port services conflict. Not supported."""
    raise NotImplementedError("scale_service is not supported on local Docker Compose")
