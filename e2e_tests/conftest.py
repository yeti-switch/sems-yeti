"""
e2e tests harness: runs SEMS with installed yeti module.
routing/cdr databases are replaced by postgresql_proxy (see etc/sems.conf)

env:
  SEMS - sems binary (default: /usr/bin/sems)
"""

import contextlib
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

from checks import UNHANDLED_SEQUENCE, AuthLog, Cdrs  # noqa: E402
from jsonrpc import JsonRpc  # noqa: E402
from profiles import YETI_AUTH_FEEDBACK, Routing  # noqa: E402
from push import PushServer  # noqa: E402
from sip import SipClient  # noqa: E402
from sip_ua import Caller, Registrant, RemoteServer, TerminationGateway  # noqa: E402

SEMS = os.environ.get("SEMS", "/usr/bin/sems")
SPOOL_DIR = os.path.join(E2E_DIR, "spool")
SEMS_LOG = os.path.join(SPOOL_DIR, "sems.log")
# written by etc/db_map/write_log.lua
CDR_FILE = os.path.join(SPOOL_DIR, "writecdr.jsonl")
AUTH_LOG_FILE = os.path.join(SPOOL_DIR, "writeauth.jsonl")
CONTROL_PORT = 5060
METRICS_URL = "http://127.0.0.1:8090/metrics"
RPC_PORT = 7080
PUSH_SERVER_PORT = 8098  # http_client destinations in etc/sems.conf
START_TIMEOUT = 30
CDR_FLUSH_WAIT = 1
STOP_TIMEOUT = 20


def _tail(path, lines=200):
    try:
        with open(path, errors="replace") as f:
            return "".join(f.readlines()[-lines:])
    except OSError as e:
        return str(e)


@contextlib.contextmanager
def run_sems(conf_path, log_path, control_port):
    """runs SEMS with the config, waits for OPTIONS reply on control_port.
    fails on startup error, crash or unclean shutdown"""
    log = open(log_path, "w")
    proc = subprocess.Popen([SEMS, "-E", "-D3", "-f", conf_path], cwd=E2E_DIR, stdout=log, stderr=subprocess.STDOUT)

    try:
        client = SipClient()
        deadline = time.monotonic() + START_TIMEOUT
        while True:
            if proc.poll() is not None:
                pytest.fail(f"sems exited during startup with code {proc.returncode}\n{_tail(log_path)}")
            reply = client.request("OPTIONS", control_port, timeout=1)
            if reply and reply.code == 200:
                break
            if time.monotonic() > deadline:
                pytest.fail(f"no 200 reply to OPTIONS in {START_TIMEOUT}s\n{_tail(log_path)}")

        yield proc

        if proc.poll() is not None:
            pytest.fail(f"sems exited during tests with code {proc.returncode}\n{_tail(log_path)}")

        time.sleep(CDR_FLUSH_WAIT)
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            pytest.fail(f"sems did not stop in {STOP_TIMEOUT}s after SIGTERM\n{_tail(log_path)}")
        if rc != 0:
            pytest.fail(f"sems exited with code {rc}\n{_tail(log_path)}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        log.close()


@pytest.fixture(scope="session")
def spool():
    """spool directories and CDR/auth log files shared by all SEMS instances of the session.
    checks CDRs after all the instances are stopped"""
    for d in ("record", "dump", "logdump", "rsr"):
        os.makedirs(os.path.join(SPOOL_DIR, d), exist_ok=True)
    for f in (CDR_FILE, AUTH_LOG_FILE):
        open(f, "w").close()

    yield SPOOL_DIR

    # CDRs of all calls made during the session (including ones not checked by tests,
    # made to SEMS variants and written on shutdown)
    unhandled = Cdrs(CDR_FILE).unhandled()
    if unhandled:
        details = "\n".join(f"orig_call_id: {c['orig_call_id']}, disconnect: {c['disconnect_code']} "
                             f"{c['disconnect_reason']}" for c in unhandled)
        pytest.fail(f"{len(unhandled)} CDRs with '{UNHANDLED_SEQUENCE}' internal disconnect reason:\n{details}")


@pytest.fixture(scope="session")
def sems(spool):
    """running SEMS instance (etc/sems.conf)"""
    with run_sems(os.path.join(E2E_DIR, "etc", "sems.conf"), SEMS_LOG, CONTROL_PORT) as proc:
        yield proc


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


@pytest.fixture
def routing(rpc):
    r = Routing(rpc)
    yield r
    r.reset()


@pytest.fixture
def caller(spool):
    """originating SIP agent"""
    c = Caller()
    yield c
    c.stop()


@pytest.fixture
def term_gw(spool):
    """termination gateway UAS on a free local UDP port"""
    gw = TerminationGateway()
    yield gw
    gw.stop()



@pytest.fixture
def cdrs(spool):
    return Cdrs(CDR_FILE)


@pytest.fixture
def auth_log(spool):
    return AuthLog(AUTH_LOG_FILE)


@pytest.fixture
def make_agent(spool):
    """factory of extra UAS agents (edge proxies, devices). stopped at the test end"""
    agents = []

    def make():
        a = TerminationGateway()
        agents.append(a)
        return a
    yield make
    for a in agents:
        a.stop()


@pytest.fixture
def make_registrant(sems):
    """factory of Registrant agents. all registered contacts are unregistered at the test end"""
    registrants = []

    def make(user, password):
        r = Registrant(user, password)
        registrants.append(r)
        return r
    yield make
    for r in registrants:
        r.unregister_all()
        r.stop()


@pytest.fixture(scope="session")
def push_server_instance():
    srv = PushServer(port=PUSH_SERVER_PORT)
    yield srv
    srv.stop()


@pytest.fixture
def push_server(push_server_instance):
    push_server_instance.reset()
    yield push_server_instance
    push_server_instance.reset()


class DbConfig:
    """
    replaces yeti configuration loaded from routing db (served by postgresql_proxy) at runtime:
    maps the loading query, increments the entity version in check_states() and requests
    yeti to check db states (yeti.request.db_states.reload) to reload changed entities
    """

    QUERIES = {
        "registrations": "SELECT * FROM load_registrations_out($1,$2)",
        "options_probers": "SELECT * FROM load_sip_options_probers($1)",
    }

    def __init__(self, rpc, states):
        self.rpc = rpc
        self.states = states  # check_states() row, shared by the session
        self.changed = set()

    def set(self, entity, rows):
        ret = self.rpc.call("postgresql_proxy.map.insert", [self.QUERIES[entity], rows])
        assert not ret, f"postgresql_proxy.map.insert failed: {ret}"
        self.states[entity] += 1
        ret = self.rpc.call("postgresql_proxy.map.insert", ["SELECT * FROM check_states()", [self.states]])
        assert not ret, f"postgresql_proxy.map.insert failed: {ret}"
        self.rpc.call("yeti.request.db_states.reload")
        self.changed.add(entity)

    def reset(self):
        for entity in self.changed:
            self.set(entity, [])
        if "registrations" in self.changed:
            # wait for unregistrations
            deadline = time.monotonic() + 3
            while self.rpc.call("yeti.show.registrations") and time.monotonic() < deadline:
                time.sleep(0.1)
        self.changed = set()


@pytest.fixture(scope="session")
def db_states(sems):
    with open(os.path.join(E2E_DIR, "etc", "db_map", "check_states.json")) as f:
        return json.load(f)[0]


@pytest.fixture
def db_config(rpc, db_states, make_remote):
    """depends on make_remote to reset configuration before remote servers are stopped"""
    cfg = DbConfig(rpc, db_states)
    yield cfg
    cfg.reset()


@pytest.fixture
def make_remote(sems):
    """factory of RemoteServer agents (remote registrars, OPTIONS targets)"""
    servers = []

    def make():
        srv = RemoteServer()
        servers.append(srv)
        return srv
    yield make
    for srv in servers:
        srv.stop()


# SEMS config variants: options read on start only. each variant runs along with the main SEMS
# with SIP/RPC/metrics ports shifted by 'shift' and own RTP range, started on the first use
AUTH_YETI_FEEDBACK = ["enable_auth_feedback = true"]

SEMS_VARIANTS = {
    "auth_feedback": {"shift": YETI_AUTH_FEEDBACK[1] - CONTROL_PORT, "yeti": AUTH_YETI_FEEDBACK},
    # yeti auth.allowed_digest_algs (RFC 7616): one challenge per algorithm, in order of preference
    "auth_sha256": {"shift": 200,
                    "yeti": AUTH_YETI_FEEDBACK + ["auth {", "    allowed_digest_algs = { SHA-256 }", "}"]},
    "auth_sha256_md5": {"shift": 300,
                        "yeti": AUTH_YETI_FEEDBACK + ["auth {", "    allowed_digest_algs = { SHA-256, MD5 }", "}"]},
    # short uac_auth nonce lifetime
    "auth_nonce_expire": {"shift": 400, "yeti": AUTH_YETI_FEEDBACK,
                          "replace": [(r"(server_secret = \S+\n)", r"\1        nonce_expire = 2\n")]},
    # transcoding codecs plugins (test_undecodable_media.py). not loaded by the main SEMS:
    # the common profile codecs group 1 has speex and GSM, so they would change all calls offers
    # SDES SRTP (srtp_seq_restart/). RTP range below the variants ones: 600 would overlap the main SEMS one
    "srtp": {"shift": 600, "rtp_low": 38000,
             "replace": [(r"(\ngeneral \{\n)", r"\1    enable_srtp = yes\n"),
                         (r"(media-interfaces \{\n    interface input \{\n)",
                          r"\1        srtp {\n            enable_srtp = yes\n            sdes {\n"
                          r"                profiles = { AES_256_CM_HMAC_SHA1_80, AES_256_CM_HMAC_SHA1_32,"
                          r" AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32 }\n            }\n        }\n")]},
    "codecs": {"shift": 500,
               "replace": [(r'(    module "amr"\{\}\n)', r'\1    module "opus"{}\n    module "speex"{}\n    module "gsm"{}\n')]},
}


def make_config_variant(path, shift, yeti=(), replace=(), rtp_low=None):
    """etc/sems.conf with shifted SIP/RPC/metrics ports, separate RTP range (derived from the shift
    or rtp_low), extra yeti options and regex replacements"""
    with open(os.path.join(E2E_DIR, "etc", "sems.conf")) as f:
        conf = f.read()
    conf = re.sub(r"(\bport = )(\d+)", lambda m: f"{m.group(1)}{int(m.group(2)) + shift}", conf)
    if rtp_low is None:
        rtp_low = 40000 + (shift // 100 - 1) * 2000
    conf = re.sub(r"low-port = \d+", f"low-port = {rtp_low}", conf)
    conf = re.sub(r"high-port = \d+", f"high-port = {rtp_low + 1999}", conf)
    marker = 'module-global "yeti" {\n'
    assert marker in conf
    conf = conf.replace(marker, marker + "".join(f"        {o}\n" for o in yeti))
    for pattern, repl in replace:
        conf, n = re.subn(pattern, repl, conf)
        assert n, f"no match for {pattern}"
    with open(path, "w") as f:
        f.write(conf)


class SemsVariant:
    def __init__(self, name, shift):
        self.name = name
        self.addr = ("127.0.0.1", CONTROL_PORT + shift)
        self.rpc = None


@pytest.fixture(scope="session")
def sems_variant(spool):
    """factory: sems_variant(name) -> running SemsVariant (addr, rpc) for SEMS_VARIANTS[name]"""
    stack = contextlib.ExitStack()
    started = {}

    def get(name):
        if name not in started:
            cfg = SEMS_VARIANTS[name]
            conf = os.path.join(SPOOL_DIR, f"sems_{name}.conf")
            make_config_variant(conf, cfg["shift"], cfg.get("yeti", ()), cfg.get("replace", ()), cfg.get("rtp_low"))
            variant = SemsVariant(name, cfg["shift"])
            stack.enter_context(run_sems(conf, os.path.join(SPOOL_DIR, f"sems_{name}.log"), variant.addr[1]))
            variant.rpc = JsonRpc(port=RPC_PORT + cfg["shift"])
            stack.callback(variant.rpc.close)
            started[name] = variant
        return started[name]

    with stack:
        yield get


@pytest.fixture(scope="session")
def rpc_auth_feedback(sems_variant):
    return sems_variant("auth_feedback").rpc
