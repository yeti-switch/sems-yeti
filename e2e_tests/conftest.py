"""
e2e tests harness: runs SEMS with installed yeti module.
routing/cdr databases are replaced by postgresql_proxy (see etc/sems.conf)

env:
  SEMS - sems binary (default: /usr/bin/sems)
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request

import pytest

E2E_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(E2E_DIR, "lib"))

from checks import UNHANDLED_SEQUENCE, Cdrs  # noqa: E402
from jsonrpc import JsonRpc  # noqa: E402
from sip import SipClient  # noqa: E402
from sip_ua import Caller, TerminationGateway  # noqa: E402

SEMS = os.environ.get("SEMS", "/usr/bin/sems")
SPOOL_DIR = os.path.join(E2E_DIR, "spool")
SEMS_LOG = os.path.join(SPOOL_DIR, "sems.log")
CDR_FILE = os.path.join(SPOOL_DIR, "cdr.jsonl")  # written by etc/db_map/writecdr.lua
CONTROL_PORT = 5060
METRICS_URL = "http://127.0.0.1:8090/metrics"
RPC_PORT = 7080
START_TIMEOUT = 30
CDR_FLUSH_WAIT = 1
STOP_TIMEOUT = 20


def _tail(path, lines=200):
    try:
        with open(path, errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError as e:
        return str(e)


@pytest.fixture(scope="session")
def sems():
    """running SEMS instance. fails the session on startup error, crash or unclean shutdown"""
    for d in ("record", "dump", "logdump", "rsr"):
        os.makedirs(os.path.join(SPOOL_DIR, d), exist_ok=True)
    open(CDR_FILE, "w").close()

    log = open(SEMS_LOG, "w")
    proc = subprocess.Popen(
        [SEMS, "-E", "-D3", "-f", os.path.join(E2E_DIR, "etc", "sems.conf")],
        cwd=E2E_DIR, stdout=log, stderr=subprocess.STDOUT)

    try:
        client = SipClient()
        deadline = time.monotonic() + START_TIMEOUT
        while True:
            if proc.poll() is not None:
                pytest.fail(f"sems exited during startup with code {proc.returncode}\n{_tail(SEMS_LOG)}")
            reply = client.request("OPTIONS", CONTROL_PORT, timeout=1)
            if reply and reply.code == 200:
                break
            if time.monotonic() > deadline:
                pytest.fail(f"no 200 reply to OPTIONS in {START_TIMEOUT}s\n{_tail(SEMS_LOG)}")

        yield proc

        if proc.poll() is not None:
            pytest.fail(f"sems exited during tests with code {proc.returncode}\n{_tail(SEMS_LOG)}")

        time.sleep(CDR_FLUSH_WAIT)
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            pytest.fail(f"sems did not stop in {STOP_TIMEOUT}s after SIGTERM\n{_tail(SEMS_LOG)}")
        if rc != 0:
            pytest.fail(f"sems exited with code {rc}\n{_tail(SEMS_LOG)}")

        # CDRs of all calls made during the session (including ones not checked by tests
        # and ones written on shutdown)
        unhandled = Cdrs(CDR_FILE).unhandled()
        if unhandled:
            details = "\n".join(f"orig_call_id: {c['orig_call_id']}, disconnect: {c['disconnect_code']} "
                                 f"{c['disconnect_reason']}" for c in unhandled)
            pytest.fail(f"{len(unhandled)} CDRs with '{UNHANDLED_SEQUENCE}' internal disconnect reason:\n{details}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        log.close()


class Metrics:
    """SEMS counters from prometheus_exporter"""

    def get(self, name):
        with urllib.request.urlopen(METRICS_URL, timeout=5) as r:
            text = r.read().decode()
        total = 0
        found = False
        for m in re.finditer(rf"^\w*_{re.escape(name)}(?:\{{[^}}]*\}})?\s+(\d+)", text, re.MULTILINE):
            total += int(m.group(1))
            found = True
        assert found, f"metric *_{name} not found in {METRICS_URL}"
        return total


@pytest.fixture
def metrics(sems):
    return Metrics()


@pytest.fixture(scope="session")
def rpc(sems):
    """jsonrpc connection to SEMS"""
    conn = JsonRpc(port=RPC_PORT)
    yield conn
    conn.close()


class Routing:
    """
    controls response of yeti routing query (prepared statement 'getprofile')
    served by postgresql_proxy. profiles are rows of the routing function result
    """

    QUERY = "getprofile"

    def __init__(self, rpc):
        self.rpc = rpc

    def set_profiles(self, profiles):
        ret = self.rpc.call("postgresql_proxy.map.insert", [self.QUERY, profiles])
        assert not ret, f"postgresql_proxy.map.insert failed: {ret}"

    def reset(self):
        """routing query fails like it is not mapped at all"""
        ret = self.rpc.call("postgresql_proxy.map.insert", [self.QUERY, None, "no routing configured by test"])
        assert not ret, f"postgresql_proxy.map.insert failed: {ret}"


@pytest.fixture
def routing(rpc):
    r = Routing(rpc)
    yield r
    r.reset()


@pytest.fixture
def caller(sems):
    """originating SIP agent"""
    c = Caller()
    yield c
    c.stop()


@pytest.fixture
def term_gw(sems):
    """termination gateway UAS on a free local UDP port"""
    gw = TerminationGateway()
    yield gw
    gw.stop()



@pytest.fixture
def cdrs(sems):
    return Cdrs(CDR_FILE)
