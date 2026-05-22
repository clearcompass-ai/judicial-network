#!/usr/bin/env python3
"""
clarity_e2e.py — one-command local end-to-end bring-up + verification for the
Clarity stack, STRICT-PULL: every service runs from a published GHCR image; the
orchestrator relies on NO source checkout of attesta-tools (the witness + auditor
images come from GHCR), only the two siblings it drives by their own launchers:

    <root>/ledger               ledger + infra (Postgres + SeaweedFS, Docker)
    <root>/judicial-network     JN enforcer + the deployment composes (this repo)

Images (override any with the matching env var; default tag = latest):

    witness     ghcr.io/<owner>/attesta-tools/witness        (daemon + gen-fixtures)
    auditor     ghcr.io/<owner>/attesta-tools/auditor        (custody + detection)
    aggregator  ghcr.io/<owner>/judicial-network/aggregator  (read-projection)
    network-api ghcr.io/<owner>/judicial-network             (JN enforcer)

It brings the tiers up IN ORDER, seeds the first entry (so the ledger produces a
cosigned tree head), stands up the external auditor (custody + detection) and the
rebuildable aggregator projection, starts the JN enforcer, and CHECKS each tier
(Separation of Duties: custody is the auditor's, the JN re-verifies):

    witnesses healthy → ledger healthy → cosigned tree head (K sigs)
        → auditor healthy (custody store + inbound verify pipeline)
        → aggregator healthy (projection db + ledger gated)
        → JN healthy (mTLS) + ready (ledger-gated) + verify-only ingest ← auditor

The witness fleet runs as containers from the published image: keys + the network
bootstrap are minted by the SAME image (--entrypoint /gen-fixtures) into a local
fixtures dir under e2e/.run/, then N daemon containers mount it. No source build.

Usage:
    ./clarity_e2e.py up        # full clean bring-up + checks (default)
    ./clarity_e2e.py down      # tear everything down
    ./clarity_e2e.py status    # probe what's currently up
    ./clarity_e2e.py up --root ~/clarity --witnesses 5 --image-tag latest

Robust by design: explicit prereq checks, health POLLING with timeouts (no blind
sleeps), per-stage logs under e2e/.run/, fail-fast diagnostics, and a teardown
that also clears stale processes / WAL locks. Stdlib only (shells out to docker +
the ledger's own scripts + curl).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

# The sibling repos the orchestrator drives by their own launchers. The witness +
# auditor are NOT here — they come from GHCR images (strict pull).
REPOS = ("ledger", "judicial-network")
SELF_DIR = Path(__file__).resolve().parent
STATE_DIR = SELF_DIR / ".run"
STATE_FILE = STATE_DIR / "state.json"
LOG_DIR = STATE_DIR / "logs"
FIXTURES_DIR = STATE_DIR / "witness-fixtures"  # minted by the witness image

# ── tiny logging ──────────────────────────────────────────────────────
_BOLD, _GREEN, _RED, _YEL, _DIM, _RST = (
    ("\033[1m", "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m")
    if sys.stdout.isatty() else ("", "", "", "", "", "")
)


def stage(msg: str) -> None:
    print(f"\n{_BOLD}== {msg} =={_RST}", flush=True)


def ok(msg: str) -> None:
    print(f"  {_GREEN}✔{_RST} {msg}", flush=True)


def info(msg: str) -> None:
    print(f"  {_DIM}{msg}{_RST}", flush=True)


def warn(msg: str) -> None:
    print(f"  {_YEL}! {msg}{_RST}", flush=True)


def die(msg: str, log: Path | None = None) -> "NoReturn":  # type: ignore[name-defined]
    print(f"\n{_RED}{_BOLD}FATAL:{_RST} {_RED}{msg}{_RST}", file=sys.stderr, flush=True)
    if log and log.exists():
        print(f"{_DIM}--- last 30 lines of {log} ---{_RST}", file=sys.stderr)
        tail = log.read_text(errors="replace").splitlines()[-30:]
        print("\n".join(tail), file=sys.stderr)
    sys.exit(1)


# ── subprocess helpers ────────────────────────────────────────────────
def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None,
        check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
    """Run a command to completion, capturing output. A missing cwd is treated as
    a failed command (returncode 127) rather than crashing the orchestrator — so
    teardown stays resilient even if a sibling repo isn't checked out."""
    if cwd is not None and not Path(cwd).is_dir():
        if check:
            die(f"working directory does not exist: {cwd}")
        if not quiet:
            info(f"skip (no cwd {cwd}): {' '.join(cmd)}")
        return subprocess.CompletedProcess(cmd, 127, "", f"cwd missing: {cwd}")
    if not quiet:
        info(f"$ {' '.join(cmd)}" + (f"  (cwd={cwd})" if cwd else ""))
    proc = subprocess.run(
        cmd, cwd=str(cwd) if cwd else None,
        env={**os.environ, **(env or {})},
        text=True, capture_output=True,
    )
    if check and proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        die(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc


def run_bg(cmd: list[str], cwd: Path, env: dict, logfile: Path) -> int:
    """Launch a long-running daemon detached (own session, survives this
    script), streaming output to logfile. Returns the process-group PID."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    fh = open(logfile, "w")
    info(f"$ {' '.join(cmd)}  (cwd={cwd}, log={logfile.name})")
    proc = subprocess.Popen(
        cmd, cwd=str(cwd), env={**os.environ, **env},
        stdout=fh, stderr=subprocess.STDOUT,
        start_new_session=True,  # own process group → killable + survives us
    )
    return proc.pid


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def docker_pull(img: str) -> None:
    """Make an image available. A locally-present image is used as-is (so a
    `name:local` override works offline / for unpublished changes); otherwise it
    is pulled from the registry. Strict-pull: nothing is ever BUILT here."""
    present = run(["docker", "image", "inspect", img], check=False, quiet=True).returncode == 0
    if present:
        info(f"using local image {img}")
        return
    run(["docker", "pull", img])


def kill_port(port: int) -> None:
    """Kill whatever listens on a TCP port (clears stale ledger/JN holding a
    WAL lock or the listener). TERM, then KILL."""
    if not have("lsof"):
        return
    pids = run(["lsof", "-ti", f"tcp:{port}"], check=False, quiet=True).stdout.split()
    for sig in (signal.SIGTERM, signal.SIGKILL):
        alive = []
        for pid in pids:
            try:
                os.kill(int(pid), sig)
                alive.append(pid)
            except (ProcessLookupError, ValueError):
                pass
        if not alive:
            break
        time.sleep(1)
    if pids:
        info(f"freed port :{port} (killed {', '.join(pids)})")


def kill_pgid(pid: int) -> None:
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    time.sleep(1)
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# ── HTTP checks (curl; dependency-free) ───────────────────────────────
def http_code(url: str, max_time: int = 5, mtls: tuple | None = None) -> int:
    cmd = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", str(max_time)]
    if mtls:
        ca, crt, key = mtls
        cmd += ["--cacert", ca, "--cert", crt, "--key", key]
    cmd.append(url)
    p = run(cmd, check=False, quiet=True)
    try:
        return int(p.stdout.strip() or "0")
    except ValueError:
        return 0


def http_body(url: str, max_time: int = 5, mtls: tuple | None = None) -> str:
    cmd = ["curl", "-sS", "--max-time", str(max_time)]
    if mtls:
        ca, crt, key = mtls
        cmd += ["--cacert", ca, "--cert", crt, "--key", key]
    cmd.append(url)
    return run(cmd, check=False, quiet=True).stdout


def poll(desc: str, fn, timeout: int, interval: float = 2.0, log: Path | None = None):
    """Call fn() until it returns truthy or timeout. fn returns the value (or
    falsy to keep waiting). Raises via die() on timeout."""
    deadline = time.time() + timeout
    attempt = 0
    last_err = ""
    while time.time() < deadline:
        attempt += 1
        try:
            val = fn()
        except Exception as e:  # noqa: BLE001 — surfacing is the point
            val = None
            last_err = str(e)
        else:
            last_err = ""
        if val:
            ok(f"{desc} (attempt {attempt})")
            return val
        time.sleep(interval)
    die(f"timed out after {timeout}s waiting for: {desc}" + (f" — {last_err}" if last_err else ""), log)


# ── state (for teardown across invocations) ───────────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def save_state(st: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(st, indent=2))


# ── config ────────────────────────────────────────────────────────────
class Cfg:
    def __init__(self, args: argparse.Namespace):
        self.root = self._discover_root(args.root)
        self.ledger = self.root / "ledger"
        self.jn = self.root / "judicial-network"
        self.deploy = self.jn / "deployment" / "local"
        self.n = args.witnesses
        self.port_base = args.port_base
        self.ledger_addr = args.ledger_addr
        self.jn_addr = args.jn_addr
        self.auditor_addr = args.auditor_addr
        self.aggregator_addr = args.aggregator_addr
        self.timeout = args.timeout
        self.keep_state = args.keep_state

        # Strict-pull image refs. Owner + tag are knobs; each image can also be
        # overridden whole (e.g. CLARITY_WITNESS_IMAGE=witness:local for an
        # unpublished local build).
        owner = args.ghcr_owner or os.environ.get("CLARITY_GHCR_OWNER", "clearcompass-ai")
        tag = args.image_tag or os.environ.get("CLARITY_IMAGE_TAG", "latest")
        reg = os.environ.get("CLARITY_REGISTRY", "ghcr.io")
        self.witness_img = os.environ.get(
            "CLARITY_WITNESS_IMAGE", f"{reg}/{owner}/attesta-tools/witness:{tag}")
        self.auditor_img = os.environ.get(
            "CLARITY_AUDITOR_IMAGE", f"{reg}/{owner}/attesta-tools/auditor:{tag}")
        self.aggregator_img = os.environ.get(
            "CLARITY_AGGREGATOR_IMAGE", f"{reg}/{owner}/judicial-network/aggregator:{tag}")
        self.network_api_img = os.environ.get(
            "CLARITY_NETWORK_API_IMAGE", f"{reg}/{owner}/judicial-network:{tag}")

    @staticmethod
    def _discover_root(explicit: str | None) -> Path:
        candidates = []
        if explicit:
            candidates.append(Path(explicit).expanduser())
        if os.environ.get("CLARITY_ROOT"):
            candidates.append(Path(os.environ["CLARITY_ROOT"]).expanduser())
        candidates.append(SELF_DIR.parent.parent)  # <root>/judicial-network/e2e → <root>
        candidates.append(Path.home() / "clarity")
        for c in candidates:
            if c and all((c / r).is_dir() for r in REPOS):
                return c.resolve()
        die("could not locate the clarity root (a dir containing "
            f"{', '.join(REPOS)}). Pass --root <dir> or set CLARITY_ROOT.")

    @property
    def ledger_port(self) -> int:
        return int(self.ledger_addr.lstrip(":").rsplit(":", 1)[-1])

    @property
    def jn_port(self) -> int:
        return int(self.jn_addr.lstrip(":").rsplit(":", 1)[-1])

    @property
    def auditor_port(self) -> int:
        return int(self.auditor_addr.lstrip(":").rsplit(":", 1)[-1])

    @property
    def aggregator_port(self) -> int:
        return int(self.aggregator_addr.lstrip(":").rsplit(":", 1)[-1])

    @property
    def certs(self) -> Path:
        return self.jn / ".run" / "certs"

    def mtls(self) -> tuple:
        return (str(self.certs / "ca.crt"),
                str(self.certs / "judge-adams.client.crt"),
                str(self.certs / "judge-adams.client.key"))


# ── prerequisites ─────────────────────────────────────────────────────
def check_prereqs(cfg: Cfg) -> None:
    stage("prerequisites")
    for b in ("curl", "docker"):
        if not have(b):
            die(f"`{b}` not on PATH")
    ok("curl, docker present")
    if run(["docker", "info"], check=False, quiet=True).returncode != 0:
        die("docker daemon not reachable (start Docker Desktop) — the stack runs in Docker only")
    ok("docker daemon reachable")
    for r in REPOS:
        if not (cfg.root / r).is_dir():
            die(f"{cfg.root / r} missing — the e2e drives the ledger + judicial-network siblings")
    ok(f"clarity root: {cfg.root}")
    info(f"images: witness={cfg.witness_img}")
    info(f"        auditor={cfg.auditor_img}")
    info(f"        aggregator={cfg.aggregator_img}")
    info(f"        network-api={cfg.network_api_img}")


# ── witness containers ────────────────────────────────────────────────
def _witness_name(i: int) -> str:
    return f"clarity-witness-{i}"


def teardown(cfg: Cfg, full: bool = True) -> None:
    stage("teardown (stop daemons, clear stale processes + WAL locks)")
    st = load_state()

    # JN first (top of the stack).
    run(["make", "jn-down"], cwd=cfg.jn, check=False, quiet=True)
    kill_port(cfg.jn_port)
    if st.get("jn_pid"):
        kill_pgid(int(st["jn_pid"]))

    # Auditor + aggregator (each compose bundles the service's own Postgres;
    # `down -v` drops the volumes for a clean next run).
    for comp in ("docker-compose.auditor.yml", "docker-compose.aggregator.yml"):
        run(["docker", "compose", "-f", str(cfg.deploy / comp), "down", "-v"],
            cwd=cfg.jn, check=False, quiet=True)
    kill_port(cfg.auditor_port)
    kill_port(cfg.aggregator_port)

    # Ledger: kill the PROCESS first to release the Badger WAL lock, THEN
    # tear down infra and (optionally) wipe local state. run-local.sh down
    # only stops infra, never the `go run` — so we must free :8080 ourselves.
    kill_port(cfg.ledger_port)
    if st.get("ledger_pid"):
        kill_pgid(int(st["ledger_pid"]))
    run([str(cfg.ledger / "scripts" / "run-local.sh"), "down"], cwd=cfg.ledger, check=False, quiet=True)
    if full:
        for sub in ("wal", "tessera", "antispam"):
            shutil.rmtree(cfg.ledger / ".run" / sub, ignore_errors=True)
        ok("ledger local state wiped (wal/tessera/antispam) — clean genesis")

    # Witness fleet: container daemons + the minted fixtures.
    names = [_witness_name(i) for i in range(1, cfg.n + 1)]
    run(["docker", "rm", "-f", *names], check=False, quiet=True)
    for i in range(cfg.n):
        kill_port(cfg.port_base + i)
    if full:
        shutil.rmtree(FIXTURES_DIR, ignore_errors=True)

    save_state({})
    ok("teardown complete")


# ── bring-up stages ───────────────────────────────────────────────────
def bring_up_witnesses(cfg: Cfg, st: dict) -> dict:
    stage(f"witness fleet (K={cfg.n}, :{cfg.port_base}..:{cfg.port_base + cfg.n - 1})  [docker pull]")
    docker_pull(cfg.witness_img)
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    uid = f"{os.getuid()}:{os.getgid()}"

    # Mint witness keys + the network bootstrap FROM the published image — the
    # daemon image bundles cmd/gen-fixtures, so no source checkout is needed.
    run(["docker", "run", "--rm", "--entrypoint", "/gen-fixtures", "--user", uid,
         "-v", f"{FIXTURES_DIR}:/out", cfg.witness_img,
         "-out-dir=/out", "-out-bootstrap=/out/network-bootstrap.json",
         f"-witnesses={cfg.n}"])
    boot = FIXTURES_DIR / "network-bootstrap.json"
    if not boot.exists():
        die(f"gen-fixtures did not produce {boot}")
    exchange_did = json.loads(boot.read_text()).get("exchange_did", "")
    if not exchange_did:
        die(f"bootstrap {boot} has no exchange_did")

    # One daemon container per witness, mounting the shared fixtures (the daemon
    # runs as the host uid so it can read the host-owned keys).
    for i in range(1, cfg.n + 1):
        port = cfg.port_base + i - 1
        run(["docker", "rm", "-f", _witness_name(i)], check=False, quiet=True)
        run(["docker", "run", "-d", "--name", _witness_name(i), "--user", uid,
             "-p", f"{port}:8081", "-v", f"{FIXTURES_DIR}:/keys:ro", cfg.witness_img,
             "-addr=:8081", f"-key-file=/keys/witnesses/witness-{i}.pem",
             "-bootstrap=/keys/network-bootstrap.json"])
    for i in range(cfg.n):
        p = cfg.port_base + i
        poll(f"witness :{p} healthy",
             lambda p=p: http_code(f"http://localhost:{p}/healthz") == 200,
             timeout=30)

    # The three LEDGER_* vars the ledger reads (matching write-env.sh), built
    # here from the fleet we just launched.
    endpoints = ",".join(f"http://localhost:{cfg.port_base + i}" for i in range(cfg.n))
    witness_env = {
        "LEDGER_NETWORK_BOOTSTRAP_FILE": str(boot),
        "LEDGER_WITNESS_ENDPOINTS": endpoints,
        "LEDGER_WITNESS_QUORUM_K": str(cfg.n),
    }
    ok(f"bootstrap: {boot}")
    ok(f"log DID:   {exchange_did}  (quorum_k={cfg.n})")
    st.update(witness_env=witness_env, bootstrap=str(boot), quorum_k=str(cfg.n), log_did=exchange_did)
    return st


def bring_up_ledger(cfg: Cfg, st: dict) -> dict:
    stage(f"ledger (SeaweedFS) on {cfg.ledger_addr}")
    log = LOG_DIR / "ledger.log"
    env = dict(st["witness_env"])
    env["LEDGER_LOG_DID"] = st["log_did"]  # match the bootstrap's log
    pid = run_bg([str(cfg.ledger / "scripts" / "run-local.sh"), "up"],
                 cwd=cfg.ledger, env=env, logfile=log)
    st["ledger_pid"] = pid
    save_state(st)
    poll("ledger /healthz == ok",
         lambda: http_body(f"http://localhost:{cfg.ledger_port}/healthz").strip() == "ok",
         timeout=cfg.timeout, log=log)
    return st


def seed_ledger(cfg: Cfg, st: dict) -> dict:
    stage("seed first entry (→ builder advances → fleet cosigns the head)")
    log = LOG_DIR / "seed.log"
    # The ledger cosigns per builder cycle; a fresh log has no cosigned head
    # until the first entry is sequenced. submit-stamp is the ledger-native
    # tool; -log-did MUST match the log or admission rejects it.
    p = run(["go", "run", "./cmd/submit-stamp",
             "-url", f"http://localhost:{cfg.ledger_port}",
             "-log-did", st["log_did"]],
            cwd=cfg.ledger, env=dict(st["witness_env"]), check=False)
    log.write_text(p.stdout + p.stderr)
    if p.returncode != 0:
        die("seed submit failed", log)
    ok("entry submitted")
    k = int(st["quorum_k"])

    def head_ready():
        body = http_body(f"http://localhost:{cfg.ledger_port}/v1/tree/head")
        try:
            h = json.loads(body)
        except json.JSONDecodeError:
            return None
        size = h.get("tree_size", 0)
        sigs = len(h.get("signatures", []) or [])
        return (size, sigs) if size >= 1 and sigs >= k else None

    size, sigs = poll(f"cosigned tree head (size>=1, sigs>={k})", head_ready,
                      timeout=cfg.timeout, log=LOG_DIR / "ledger.log")
    ok(f"cosigned head: tree_size={size}, witness_sigs={sigs}")
    return st


def bring_up_auditor(cfg: Cfg, st: dict) -> dict:
    stage(f"auditor (evidence custodian + detection) on {cfg.auditor_addr}  [docker pull]")
    docker_pull(cfg.auditor_img)
    compose = cfg.deploy / "docker-compose.auditor.yml"
    env = {
        "AUDITOR_IMAGE": cfg.auditor_img,
        "AUDITOR_BOOTSTRAP_FILE": st["bootstrap"],
        "AUDITOR_WITNESS_QUORUM_K": str(st["quorum_k"]),
        # Pull + re-verify the ledger's raw /v1/gossip; persist + serve our own.
        "AUDITOR_PEERS": f'{st["log_did"]}=http://host.docker.internal:{cfg.ledger_port}',
    }
    run(["docker", "compose", "-f", str(compose), "up", "-d"], cwd=cfg.jn, env=env)
    poll("auditor /healthz == ok",
         lambda: http_body(f"http://localhost:{cfg.auditor_port}/healthz").strip() == "ok",
         timeout=cfg.timeout)
    poll("auditor /readyz == 200",
         lambda: http_code(f"http://localhost:{cfg.auditor_port}/readyz") == 200,
         timeout=cfg.timeout)
    # Active integrity detection + custody now live HERE (re-homed from the JN by
    # the SoD split): the auditor stands up its durable store + inbound verify
    # pipeline (pull → SDK finding router → reconcile → persist → serve /v1/gossip).
    dl = run(["docker", "logs", "attesta-auditor"], check=False, quiet=True)
    if "custody + inbound pipeline up" in (dl.stdout + dl.stderr):
        ok("auditor custody + inbound verify pipeline up (detection re-homed here)")
    else:
        warn("auditor custody-pipeline log line not seen yet (store/peers configured?)")
    return st


def bring_up_aggregator(cfg: Cfg, st: dict) -> dict:
    stage(f"aggregator (rebuildable read-projection) on {cfg.aggregator_addr}  [docker pull]")
    docker_pull(cfg.aggregator_img)
    compose = cfg.deploy / "docker-compose.aggregator.yml"
    env = {
        "AGG_IMAGE": cfg.aggregator_img,
        "TOOLS_LEDGER_URL": f"http://host.docker.internal:{cfg.ledger_port}",
        # The e2e network has one bootstrap log; point all three scan logs at it.
        "TOOLS_OFFICERS_LOG": st["log_did"],
        "TOOLS_CASES_LOG": st["log_did"],
        "TOOLS_PARTIES_LOG": st["log_did"],
    }
    run(["docker", "compose", "-f", str(compose), "up", "-d"], cwd=cfg.jn, env=env)
    poll("aggregator /healthz == 200",
         lambda: http_code(f"http://localhost:{cfg.aggregator_port}/healthz") == 200,
         timeout=cfg.timeout)
    # /readyz gates on BOTH Postgres + the ledger — proves the projection DB is
    # migrated + wired and the ledger scan source is reachable.
    poll("aggregator /readyz == 200 (db + ledger gated)",
         lambda: http_code(f"http://localhost:{cfg.aggregator_port}/readyz") == 200,
         timeout=cfg.timeout)
    ok("aggregator projection up (self-migrated; rebuildable from watermark 0)")
    return st


def bring_up_jn(cfg: Cfg, st: dict) -> dict:
    stage(f"JN enforcer (network-api) on {cfg.jn_addr}  [docker pull]")
    docker_pull(cfg.network_api_img)
    log = LOG_DIR / "jn.log"
    # run-jn.sh pulls the published image (JN_IMAGE_PULL=1) instead of building;
    # the verify-only ingest points at the host-published auditor by default.
    env = {
        "LEDGER_NETWORK_BOOTSTRAP_FILE": st["bootstrap"],
        "LEDGER_WITNESS_QUORUM_K": str(st["quorum_k"]),
        "JN_IMAGE_PULL": "1",
        "JN_IMAGE": cfg.network_api_img,
    }
    pid = run_bg([str(cfg.jn / "scripts" / "run-jn.sh"), "up"],
                 cwd=cfg.jn, env=env, logfile=log)
    st["jn_pid"] = pid
    save_state(st)

    if not (cfg.certs / "ca.crt").exists():
        # run-jn.sh mints identity on first run; give it a moment.
        poll("mTLS certs minted", lambda: (cfg.certs / "ca.crt").exists(), timeout=60, log=log)
    mtls = cfg.mtls()
    poll("JN /healthz == ok (mTLS)",
         lambda: http_body(f"https://localhost:{cfg.jn_port}/healthz", mtls=mtls).strip() == "ok",
         timeout=cfg.timeout, log=log)
    poll("JN /readyz == 200 (ledger-gated)",
         lambda: http_code(f"https://localhost:{cfg.jn_port}/readyz", mtls=mtls) == 200,
         timeout=cfg.timeout, log=log)
    # The JN is the ENFORCER: admission/enforcement on the commit clock + a
    # verify-only gossip pull from the auditor. Custody + detection moved to the
    # external auditor (SoD). Best-effort log scan for the verify-only ingest.
    txt = log.read_text(errors="replace") if log.exists() else ""
    dl = run(["docker", "logs", "jn-network-api"], check=False, quiet=True)
    txt += dl.stdout + dl.stderr
    if "gossip ingest pulling" in txt:
        ok("JN verify-only gossip ingest pulling the auditor feed")
    return st


def summary(cfg: Cfg, st: dict) -> None:
    stage("STACK UP — end-to-end verified")
    c = cfg.certs
    print(f"""  witnesses : :{cfg.port_base}..:{cfg.port_base + cfg.n - 1}   (K={st['quorum_k']})
  ledger    : http://localhost:{cfg.ledger_port}      log={st['log_did']}
  auditor   : http://localhost:{cfg.auditor_port}      (evidence custodian + detection; serves /v1/gossip)
  aggregator: http://localhost:{cfg.aggregator_port}      (rebuildable read-projection)
  JN enforcer: https://localhost:{cfg.jn_port}    (mTLS; verify-only ingest ← auditor)
  bootstrap : {st['bootstrap']}

  health (JN, needs a client cert):
    curl --cacert {c}/ca.crt \\
         --cert {c}/judge-adams.client.crt \\
         --key  {c}/judge-adams.client.key https://localhost:{cfg.jn_port}/healthz

  logs   : {LOG_DIR}/
  tear down: {Path(__file__).name} down
""")


# ── commands ──────────────────────────────────────────────────────────
def cmd_up(cfg: Cfg) -> None:
    check_prereqs(cfg)
    if not cfg.keep_state:
        teardown(cfg, full=True)
    st: dict = {}
    save_state(st)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    st = bring_up_witnesses(cfg, st)
    st = bring_up_ledger(cfg, st)
    st = seed_ledger(cfg, st)
    st = bring_up_auditor(cfg, st)
    st = bring_up_aggregator(cfg, st)
    st = bring_up_jn(cfg, st)
    save_state(st)
    summary(cfg, st)


def cmd_down(cfg: Cfg) -> None:
    teardown(cfg, full=True)


def cmd_status(cfg: Cfg) -> None:
    stage("status")
    for i in range(cfg.n):
        p = cfg.port_base + i
        up = http_code(f"http://localhost:{p}/healthz") == 200
        print(f"  witness :{p:<6} {'UP' if up else 'down'}")
    led = http_body(f"http://localhost:{cfg.ledger_port}/healthz").strip() == "ok"
    print(f"  ledger  :{cfg.ledger_port:<6} {'UP' if led else 'down'}")
    if led:
        body = http_body(f"http://localhost:{cfg.ledger_port}/v1/tree/head")
        try:
            h = json.loads(body)
            print(f"     tree_size={h.get('tree_size')} witness_sigs={len(h.get('signatures', []) or [])}")
        except json.JSONDecodeError:
            print("     (no cosigned tree head yet)")
    aud = http_body(f"http://localhost:{cfg.auditor_port}/healthz").strip() == "ok"
    print(f"  auditor :{cfg.auditor_port:<6} {'UP' if aud else 'down'}")
    agg = http_code(f"http://localhost:{cfg.aggregator_port}/healthz") == 200
    print(f"  aggreg  :{cfg.aggregator_port:<6} {'UP' if agg else 'down'}")
    code = http_code(f"https://localhost:{cfg.jn_port}/healthz", mtls=cfg.mtls()) if cfg.certs.exists() else 0
    print(f"  JN      :{cfg.jn_port:<6} {'UP' if code == 200 else 'down'}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Clarity local end-to-end orchestrator (strict GHCR pull).")
    ap.add_argument("command", nargs="?", default="up", choices=["up", "down", "status"])
    ap.add_argument("--root", help="clarity root (dir holding ledger + judicial-network); else $CLARITY_ROOT, script location, or ~/clarity")
    ap.add_argument("--witnesses", type=int, default=5)
    ap.add_argument("--port-base", type=int, default=19001)
    ap.add_argument("--ledger-addr", default=":8080")
    ap.add_argument("--jn-addr", default=":8443")
    ap.add_argument("--auditor-addr", default=":8088")
    ap.add_argument("--aggregator-addr", default=":8092")
    ap.add_argument("--image-tag", help="image tag to pull (default: latest / $CLARITY_IMAGE_TAG)")
    ap.add_argument("--ghcr-owner", help="GHCR owner (default: clearcompass-ai / $CLARITY_GHCR_OWNER)")
    ap.add_argument("--timeout", type=int, default=120, help="per-stage health timeout (s)")
    ap.add_argument("--keep-state", action="store_true", help="skip the clean teardown before `up`")
    args = ap.parse_args()
    cfg = Cfg(args)
    {"up": cmd_up, "down": cmd_down, "status": cmd_status}[args.command](cfg)


if __name__ == "__main__":
    main()
