#!/usr/bin/env python3
"""
clarity.py — self-contained, image-only orchestrator for the full Clarity stack.

Depends on NOTHING from any repo: every tier runs from a published GHCR image,
and the only host tools it needs are docker, python3, openssl, and curl. Copy
this one file anywhere and run it — no ledger / attesta-tools / witness checkout,
no go toolchain, no clarity "root".

It brings up, on a single docker network, in dependency order — each
health-checked — and lets you size the witness fleet:

    fixtures (witness image: gen-fixtures)  →  mTLS certs (openssl)
      →  postgres + seaweedfs (+ bucket)    →  K witnesses
      →  ledger (image; postgres + s3 + witness wiring)  →  seed (ledger image: submit-stamp)
      →  auditor (+ its postgres)           →  aggregator (+ its postgres)
      →  JN enforcer (network-api; mTLS, verify-only ingest ← auditor)

Images (override any with the matching env var; default tag = latest):
    witness     ghcr.io/<owner>/attesta-tools/witness
    auditor     ghcr.io/<owner>/attesta-tools/auditor
    aggregator  ghcr.io/<owner>/judicial-network/aggregator
    network-api ghcr.io/<owner>/judicial-network
    ledger      ghcr.io/<owner>/ledger

Usage:
    ./clarity.py up --witnesses 5        # bring up (default 3 witnesses)
    ./clarity.py down                    # tear everything down
    ./clarity.py status                  # probe what's up
    ./clarity.py up --image-tag v1.15.0 --ghcr-owner clearcompass-ai
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

NET = "clarity-net"
PREFIX = "clarity"
HOME = Path(os.environ.get("CLARITY_HOME", str(Path.home() / ".clarity")))
FIXTURES = HOME / "fixtures"   # bootstrap + witness keys (minted by the witness image)
CERTS = HOME / "certs"         # mTLS material (minted by openssl)

POSTGRES_IMAGE = os.environ.get("CLARITY_POSTGRES_IMAGE", "postgres:16-alpine")
SEAWEED_IMAGE = os.environ.get("CLARITY_SEAWEED_IMAGE", "chrislusf/seaweedfs:3.71")

# ── logging ───────────────────────────────────────────────────────────
_B, _G, _R, _Y, _D, _0 = (
    ("\033[1m", "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m")
    if sys.stdout.isatty() else ("",) * 6
)
def stage(m): print(f"\n{_B}== {m} =={_0}", flush=True)
def ok(m): print(f"  {_G}✔{_0} {m}", flush=True)
def info(m): print(f"  {_D}{m}{_0}", flush=True)
def warn(m): print(f"  {_Y}! {m}{_0}", flush=True)
def die(m):
    print(f"\n{_R}{_B}FATAL:{_0} {_R}{m}{_0}", file=sys.stderr, flush=True)
    sys.exit(1)


# ── shell / docker helpers ────────────────────────────────────────────
def sh(cmd, check=True, quiet=False, env=None):
    if not quiet:
        info("$ " + " ".join(cmd))
    p = subprocess.run(cmd, text=True, capture_output=True,
                       env={**os.environ, **(env or {})})
    if check and p.returncode != 0:
        sys.stderr.write(p.stdout + p.stderr)
        die("command failed: " + " ".join(cmd))
    return p


def have(b): return shutil.which(b) is not None
def dname(s): return f"{PREFIX}-{s}"
def drm(*names): sh(["docker", "rm", "-f", *names], check=False, quiet=True)
def dlogs(name): return sh(["docker", "logs", name], check=False, quiet=True)
def dpull(img):
    if sh(["docker", "image", "inspect", img], check=False, quiet=True).returncode == 0:
        info(f"using local image {img}")
    else:
        sh(["docker", "pull", img])


def curl(url, mtls=None, max_time=5, body=False):
    cmd = ["curl", "-sS", "--max-time", str(max_time)]
    if not body:
        cmd += ["-o", "/dev/null", "-w", "%{http_code}"]
    if mtls:
        cmd += ["--cacert", mtls[0], "--cert", mtls[1], "--key", mtls[2]]
    cmd.append(url)
    out = sh(cmd, check=False, quiet=True).stdout
    return out if body else (int(out.strip() or "0") if out.strip().isdigit() else 0)


def poll(desc, fn, timeout, interval=2.0):
    deadline = time.time() + timeout
    n = 0
    while time.time() < deadline:
        n += 1
        try:
            if fn():
                ok(f"{desc} (attempt {n})")
                return True
        except Exception:
            pass
        time.sleep(interval)
    die(f"timed out after {timeout}s waiting for: {desc}")


# ── config ────────────────────────────────────────────────────────────
class Cfg:
    def __init__(self, a):
        owner = a.ghcr_owner or os.environ.get("CLARITY_GHCR_OWNER", "clearcompass-ai")
        tag = a.image_tag or os.environ.get("CLARITY_IMAGE_TAG", "latest")
        reg = os.environ.get("CLARITY_REGISTRY", "ghcr.io")
        self.witness = os.environ.get("CLARITY_WITNESS_IMAGE", f"{reg}/{owner}/attesta-tools/witness:{tag}")
        self.auditor = os.environ.get("CLARITY_AUDITOR_IMAGE", f"{reg}/{owner}/attesta-tools/auditor:{tag}")
        self.aggregator = os.environ.get("CLARITY_AGGREGATOR_IMAGE", f"{reg}/{owner}/judicial-network/aggregator:{tag}")
        self.network_api = os.environ.get("CLARITY_NETWORK_API_IMAGE", f"{reg}/{owner}/judicial-network:{tag}")
        self.ledger = os.environ.get("CLARITY_LEDGER_IMAGE", f"{reg}/{owner}/ledger:{tag}")
        self.n = a.witnesses
        self.k = a.quorum_k or a.witnesses
        self.witness_port_base = a.witness_port_base
        self.ledger_port = a.ledger_port
        self.auditor_port = a.auditor_port
        self.aggregator_port = a.aggregator_port
        self.jn_port = a.jn_port
        self.caller_did = a.caller_did
        self.timeout = a.timeout
        self.keep = a.keep

    def images(self):
        return [self.witness, self.auditor, self.aggregator, self.network_api, self.ledger]

    def mtls(self):
        return (str(CERTS / "ca.crt"), str(CERTS / "client.crt"), str(CERTS / "client.key"))


# ── teardown ──────────────────────────────────────────────────────────
def witness_names(cfg): return [dname(f"witness-{i}") for i in range(1, cfg.n + 1)]


def teardown(cfg):
    stage("teardown")
    names = [dname(s) for s in ("jn", "aggregator", "aggregator-db", "auditor",
                                "auditor-db", "ledger", "seaweedfs", "postgres")]
    names += witness_names(cfg)
    drm(*names)
    sh(["docker", "network", "rm", NET], check=False, quiet=True)
    shutil.rmtree(HOME, ignore_errors=True)
    ok("removed containers, network, and state")


# ── stages ────────────────────────────────────────────────────────────
def preflight(cfg):
    stage("prerequisites (no repo checkout required)")
    for b in ("docker", "openssl", "curl"):
        if not have(b):
            die(f"`{b}` not on PATH")
    if sh(["docker", "info"], check=False, quiet=True).returncode != 0:
        die("docker daemon not reachable")
    ok("docker, openssl, curl present; daemon reachable")
    for img in cfg.images():
        info(f"image: {img}")


def net_up():
    sh(["docker", "network", "create", NET], check=False, quiet=True)


def pull_all(cfg):
    stage("pull images")
    for img in cfg.images():
        dpull(img)


def mint_fixtures(cfg):
    stage(f"fixtures — mint {cfg.n} witness keys + the network bootstrap (witness image)")
    FIXTURES.mkdir(parents=True, exist_ok=True)
    uid = f"{os.getuid()}:{os.getgid()}"
    sh(["docker", "run", "--rm", "--entrypoint", "/gen-fixtures", "--user", uid,
        "-v", f"{FIXTURES}:/out", cfg.witness,
        "-out-dir=/out", "-out-bootstrap=/out/network-bootstrap.json",
        f"-witnesses={cfg.n}"])
    boot = FIXTURES / "network-bootstrap.json"
    if not boot.exists():
        die(f"gen-fixtures did not produce {boot}")
    did = json.loads(boot.read_text()).get("exchange_did", "")
    if not did:
        die("bootstrap has no exchange_did")
    ok(f"bootstrap log DID: {did}  (quorum_k={cfg.k})")
    return did


def mint_certs(cfg):
    stage(f"mTLS certs — CA + server(localhost) + client(URI SAN={cfg.caller_did}) [openssl]")
    CERTS.mkdir(parents=True, exist_ok=True)
    d = str(CERTS)
    san_srv = CERTS / "srv.ext"
    san_cli = CERTS / "cli.ext"
    san_srv.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    san_cli.write_text(f"subjectAltName=URI:{cfg.caller_did}\nextendedKeyUsage=clientAuth\n")
    R = lambda *c: sh(list(c), quiet=True)
    R("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{d}/ca.key")
    R("openssl", "req", "-x509", "-new", "-key", f"{d}/ca.key", "-sha256", "-days", "365",
      "-subj", "/CN=attesta-dev-ca", "-out", f"{d}/ca.crt")
    for who, ext, cn in (("server", san_srv, "localhost"), ("client", san_cli, cfg.caller_did)):
        R("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{d}/{who}.key")
        R("openssl", "req", "-new", "-key", f"{d}/{who}.key", "-subj", f"/CN={cn}", "-out", f"{d}/{who}.csr")
        R("openssl", "x509", "-req", "-in", f"{d}/{who}.csr", "-CA", f"{d}/ca.crt", "-CAkey", f"{d}/ca.key",
          "-CAcreateserial", "-days", "365", "-sha256", "-extfile", str(ext), "-out", f"{d}/{who}.crt")
    for f in ("server.csr", "client.csr", "ca.srl", "srv.ext", "cli.ext"):
        (CERTS / f).unlink(missing_ok=True)
    ok("CA + server + client certs minted")


def up_postgres(name, db):
    sh(["docker", "run", "-d", "--name", name, "--network", NET,
        "-e", "POSTGRES_USER=attesta", "-e", "POSTGRES_PASSWORD=attesta", "-e", f"POSTGRES_DB={db}",
        POSTGRES_IMAGE,
        "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"])
    poll(f"{name} ready",
         lambda: sh(["docker", "exec", name, "pg_isready", "-U", "attesta", "-d", db],
                    check=False, quiet=True).returncode == 0, timeout=60)


def up_infra(cfg):
    stage("ledger infra — postgres + seaweedfs (+ bucket)")
    up_postgres(dname("postgres"), "attesta_test")
    sh(["docker", "run", "-d", "--name", dname("seaweedfs"), "--network", NET, SEAWEED_IMAGE,
        "server", "-s3", "-s3.port=8333", "-s3.allowEmptyFolder=true", "-ip.bind=0.0.0.0"])
    poll("seaweedfs ready",
         lambda: sh(["docker", "exec", dname("seaweedfs"), "wget", "-q", "--spider",
                     "http://localhost:9333/cluster/status"], check=False, quiet=True).returncode == 0,
         timeout=60)
    # one-shot bucket create (weed shell talks to the master over gRPC)
    sh(["docker", "run", "--rm", "--network", NET, "--entrypoint", "/bin/sh", SEAWEED_IMAGE,
        "-c", "sleep 2; echo 's3.bucket.create -name attesta-bytes' | "
              f"weed shell -master {dname('seaweedfs')}:9333"])
    ok("postgres + seaweedfs up; bucket attesta-bytes ready")


def up_witnesses(cfg):
    stage(f"witness fleet (K={cfg.n}, :{cfg.witness_port_base}..:{cfg.witness_port_base + cfg.n - 1})")
    uid = f"{os.getuid()}:{os.getgid()}"
    for i in range(1, cfg.n + 1):
        port = cfg.witness_port_base + i - 1
        sh(["docker", "run", "-d", "--name", dname(f"witness-{i}"), "--network", NET, "--user", uid,
            "-p", f"{port}:8081", "-v", f"{FIXTURES}:/keys:ro", cfg.witness,
            "-addr=:8081", f"-key-file=/keys/witnesses/witness-{i}.pem",
            "-bootstrap=/keys/network-bootstrap.json"])
    for i in range(cfg.n):
        p = cfg.witness_port_base + i
        poll(f"witness :{p} healthy", lambda p=p: curl(f"http://localhost:{p}/healthz") == 200, timeout=30)


def up_ledger(cfg, did):
    stage(f"ledger (image; postgres + s3 + {cfg.n} witnesses) on :{cfg.ledger_port}")
    endpoints = ",".join(f"http://{dname(f'witness-{i}')}:8081" for i in range(1, cfg.n + 1))
    env = {
        "LEDGER_DATABASE_URL": f"postgres://attesta:attesta@{dname('postgres')}:5432/attesta_test?sslmode=disable",
        "LEDGER_LOG_DID": did,
        "LEDGER_ADDR": ":8080",
        "LEDGER_BYTE_STORE_BACKEND": "s3",
        "LEDGER_BYTE_STORE_S3_ENDPOINT": f"http://{dname('seaweedfs')}:8333",
        "LEDGER_BYTE_STORE_S3_BUCKET": "attesta-bytes",
        "LEDGER_BYTE_STORE_S3_REGION": "us-east-1",
        "LEDGER_BYTE_STORE_S3_ACCESS_KEY": "any",
        "LEDGER_BYTE_STORE_S3_SECRET_KEY": "any",
        "LEDGER_BYTE_STORE_S3_PATH_STYLE": "true",
        "LEDGER_WITNESS_ENDPOINTS": endpoints,
        "LEDGER_WITNESS_QUORUM_K": str(cfg.k),
        "LEDGER_NETWORK_BOOTSTRAP_FILE": "/run/clarity/network-bootstrap.json",
        "LEDGER_TESSERA_STORAGE_DIR": "/var/lib/ledger/tessera",
        "LEDGER_WAL_PATH": "/var/lib/ledger/wal",
        "LEDGER_TESSERA_ANTISPAM_PATH": "/var/lib/ledger/antispam",
    }
    args = ["docker", "run", "-d", "--name", dname("ledger"), "--network", NET,
            "-p", f"{cfg.ledger_port}:8080",
            "-v", f"{FIXTURES}:/run/clarity:ro",
            "-v", f"{dname('ledger-tessera')}:/var/lib/ledger/tessera",
            "-v", f"{dname('ledger-wal')}:/var/lib/ledger/wal",
            "-v", f"{dname('ledger-antispam')}:/var/lib/ledger/antispam"]
    for kv in env.items():
        args += ["-e", f"{kv[0]}={kv[1]}"]
    args.append(cfg.ledger)
    sh(args)
    poll("ledger /healthz == ok",
         lambda: curl(f"http://localhost:{cfg.ledger_port}/healthz", body=True).strip() == "ok",
         timeout=cfg.timeout)


def seed(cfg, did):
    stage("seed first entry (ledger image: submit-stamp) → fleet cosigns the head")
    p = sh(["docker", "run", "--rm", "--network", NET, "--entrypoint", "/submit-stamp", cfg.ledger,
            "-url", f"http://{dname('ledger')}:8080", "-log-did", did], check=False)
    if p.returncode != 0:
        sys.stderr.write(p.stdout + p.stderr)
        die("seed submit failed")
    ok("entry submitted")

    def head():
        b = curl(f"http://localhost:{cfg.ledger_port}/v1/tree/head", body=True)
        try:
            h = json.loads(b)
        except json.JSONDecodeError:
            return False
        return h.get("tree_size", 0) >= 1 and len(h.get("signatures", []) or []) >= cfg.k
    poll(f"cosigned tree head (size>=1, sigs>={cfg.k})", head, timeout=cfg.timeout)


def up_auditor(cfg, did):
    stage(f"auditor (evidence custodian + detection) on :{cfg.auditor_port}")
    up_postgres(dname("auditor-db"), "auditor_gossip")
    env = {
        "AUDITOR_LISTEN_ADDR": ":8088",
        "AUDITOR_GOSSIP_DSN": f"postgres://attesta:attesta@{dname('auditor-db')}:5432/auditor_gossip?sslmode=disable",
        "AUDITOR_NETWORK_BOOTSTRAP_FILE": "/run/clarity/network-bootstrap.json",
        "AUDITOR_WITNESS_QUORUM_K": str(cfg.k),
        "AUDITOR_PEERS": f"{did}=http://{dname('ledger')}:8080",
    }
    args = ["docker", "run", "-d", "--name", dname("auditor"), "--network", NET,
            "-p", f"{cfg.auditor_port}:8088", "-v", f"{FIXTURES}:/run/clarity:ro"]
    for kv in env.items():
        args += ["-e", f"{kv[0]}={kv[1]}"]
    args.append(cfg.auditor)
    sh(args)
    poll("auditor /healthz == ok",
        lambda: curl(f"http://localhost:{cfg.auditor_port}/healthz", body=True).strip() == "ok", timeout=cfg.timeout)
    poll("auditor /readyz == 200", lambda: curl(f"http://localhost:{cfg.auditor_port}/readyz") == 200, timeout=cfg.timeout)
    if "custody + inbound pipeline up" in (dlogs(dname("auditor")).stdout + dlogs(dname("auditor")).stderr):
        ok("auditor custody + inbound verify pipeline up")
    else:
        warn("auditor custody-pipeline log line not seen yet")


def up_aggregator(cfg, did):
    stage(f"aggregator (rebuildable read-projection) on :{cfg.aggregator_port}")
    up_postgres(dname("aggregator-db"), "aggregator")
    env = {
        "TOOLS_DATABASE_URL": f"postgres://attesta:attesta@{dname('aggregator-db')}:5432/aggregator?sslmode=disable",
        "TOOLS_LEDGER_URL": f"http://{dname('ledger')}:8080",
        "TOOLS_OFFICERS_LOG": did, "TOOLS_CASES_LOG": did, "TOOLS_PARTIES_LOG": did,
    }
    args = ["docker", "run", "-d", "--name", dname("aggregator"), "--network", NET,
            "-p", f"{cfg.aggregator_port}:8092"]
    for kv in env.items():
        args += ["-e", f"{kv[0]}={kv[1]}"]
    args.append(cfg.aggregator)
    sh(args)
    poll("aggregator /healthz == 200", lambda: curl(f"http://localhost:{cfg.aggregator_port}/healthz") == 200, timeout=cfg.timeout)
    poll("aggregator /readyz == 200 (db + ledger gated)",
         lambda: curl(f"http://localhost:{cfg.aggregator_port}/readyz") == 200, timeout=cfg.timeout)


def up_jn(cfg):
    stage(f"JN enforcer (network-api; mTLS, verify-only ingest ← auditor) on :{cfg.jn_port}")
    env = {
        "API_LISTEN_ADDR": ":8443",
        "API_LEDGER_ENDPOINT": f"http://{dname('ledger')}:8080",
        "API_NETWORK_BOOTSTRAP_FILE": "/run/clarity/network-bootstrap.json",
        "API_WITNESS_QUORUM_K": str(cfg.k),
        "API_GOSSIP_INGEST_ENABLED": "true",
        "API_GOSSIP_INGEST_PEER_URL": f"http://{dname('auditor')}:8088",
        "API_AUTH_CLIENT_CA_FILE": "/run/certs/ca.crt",
        "API_AUTH_TLS_CERT_FILE": "/run/certs/server.crt",
        "API_AUTH_TLS_KEY_FILE": "/run/certs/server.key",
    }
    args = ["docker", "run", "-d", "--name", dname("jn"), "--network", NET,
            "-p", f"{cfg.jn_port}:8443",
            "-v", f"{FIXTURES}:/run/clarity:ro", "-v", f"{CERTS}:/run/certs:ro"]
    for kv in env.items():
        args += ["-e", f"{kv[0]}={kv[1]}"]
    args.append(cfg.network_api)
    sh(args)
    m = cfg.mtls()
    poll("JN /healthz == ok (mTLS)",
         lambda: curl(f"https://localhost:{cfg.jn_port}/healthz", mtls=m, body=True).strip() == "ok", timeout=cfg.timeout)
    poll("JN /readyz == 200 (ledger-gated)",
         lambda: curl(f"https://localhost:{cfg.jn_port}/readyz", mtls=m) == 200, timeout=cfg.timeout)
    if "gossip ingest pulling" in (dlogs(dname("jn")).stdout + dlogs(dname("jn")).stderr):
        ok("JN verify-only gossip ingest pulling the auditor feed")


def summary(cfg, did):
    stage("STACK UP — image-only, end-to-end")
    c = CERTS
    print(f"""  witnesses : :{cfg.witness_port_base}..:{cfg.witness_port_base + cfg.n - 1}   (K={cfg.k})
  ledger    : http://localhost:{cfg.ledger_port}      log={did}
  auditor   : http://localhost:{cfg.auditor_port}      (custody + detection; serves /v1/gossip)
  aggregator: http://localhost:{cfg.aggregator_port}      (rebuildable read-projection)
  JN enforcer: https://localhost:{cfg.jn_port}    (mTLS; verify-only ingest ← auditor)

  JN health (needs the client cert):
    curl --cacert {c}/ca.crt --cert {c}/client.crt --key {c}/client.key \\
         https://localhost:{cfg.jn_port}/healthz

  tear down: {Path(__file__).name} down
""")


# ── commands ──────────────────────────────────────────────────────────
def cmd_up(cfg):
    preflight(cfg)
    if not cfg.keep:
        teardown(cfg)
    net_up()
    pull_all(cfg)
    did = mint_fixtures(cfg)
    mint_certs(cfg)
    up_infra(cfg)
    up_witnesses(cfg)
    up_ledger(cfg, did)
    seed(cfg, did)
    up_auditor(cfg, did)
    up_aggregator(cfg, did)
    up_jn(cfg)
    summary(cfg, did)


def cmd_down(cfg):
    teardown(cfg)


def cmd_status(cfg):
    stage("status")
    for i in range(cfg.n):
        p = cfg.witness_port_base + i
        print(f"  witness :{p:<6} {'UP' if curl(f'http://localhost:{p}/healthz') == 200 else 'down'}")
    led = curl(f"http://localhost:{cfg.ledger_port}/healthz", body=True).strip() == "ok"
    print(f"  ledger  :{cfg.ledger_port:<6} {'UP' if led else 'down'}")
    print(f"  auditor :{cfg.auditor_port:<6} {'UP' if curl(f'http://localhost:{cfg.auditor_port}/healthz', body=True).strip() == 'ok' else 'down'}")
    print(f"  aggreg  :{cfg.aggregator_port:<6} {'UP' if curl(f'http://localhost:{cfg.aggregator_port}/healthz') == 200 else 'down'}")
    code = curl(f"https://localhost:{cfg.jn_port}/healthz", mtls=cfg.mtls()) if (CERTS / "ca.crt").exists() else 0
    print(f"  JN      :{cfg.jn_port:<6} {'UP' if code == 200 else 'down'}")


def main():
    ap = argparse.ArgumentParser(description="Self-contained, image-only Clarity stack orchestrator.")
    ap.add_argument("command", nargs="?", default="up", choices=["up", "down", "status"])
    ap.add_argument("--witnesses", type=int, default=3, help="witness fleet size (default 3)")
    ap.add_argument("--quorum-k", type=int, default=0, help="K-of-N quorum (default = --witnesses)")
    ap.add_argument("--image-tag", help="image tag to pull (default: latest / $CLARITY_IMAGE_TAG)")
    ap.add_argument("--ghcr-owner", help="GHCR owner (default: clearcompass-ai / $CLARITY_GHCR_OWNER)")
    ap.add_argument("--witness-port-base", type=int, default=19001)
    ap.add_argument("--ledger-port", type=int, default=8080)
    ap.add_argument("--auditor-port", type=int, default=8088)
    ap.add_argument("--aggregator-port", type=int, default=8092)
    ap.add_argument("--jn-port", type=int, default=8443)
    ap.add_argument("--caller-did", default="did:web:state:tn:davidson", help="client-cert URI SAN (authenticated caller)")
    ap.add_argument("--timeout", type=int, default=180, help="per-stage health timeout (s)")
    ap.add_argument("--keep", action="store_true", help="skip the clean teardown before up")
    a = ap.parse_args()
    cfg = Cfg(a)
    {"up": cmd_up, "down": cmd_down, "status": cmd_status}[a.command](cfg)


if __name__ == "__main__":
    main()
