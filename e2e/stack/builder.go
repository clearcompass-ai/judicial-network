package stack

import (
	"fmt"
	"github.com/clearcompass-ai/judicial-network/e2e/internal/bootstrap"
	"path/filepath"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
	"github.com/clearcompass-ai/judicial-network/e2e/runstore"
	"github.com/clearcompass-ai/judicial-network/e2e/topology"
)

func stage(format string, a ...any) { fmt.Printf("== "+format+" ==\n", a...) }
func okf(format string, a ...any)   { fmt.Printf("  ✔ "+format+"\n", a...) }

// Build realises a StackSpec under runID: shared infra (postgres + object store),
// then per network a witness fleet, a ledger, auditors, and — when HasJN — a JN
// enforcer. The brought-up stack is PERSISTED to the run store so status/run/wipe
// can address it later. Build tears down any prior containers for this run id first
// (idempotent at the container level).
func Build(spec topology.StackSpec, runID string) (*runstore.Manifest, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	lay, err := runstore.New(runID)
	if err != nil {
		return nil, err
	}
	if err := lay.Mkdirs(); err != nil {
		return nil, err
	}
	images := ResolveImages()
	ncs := DeriveNetConfigs(spec, runID)
	network := ncs[0].Network
	prefix := "baseproof-" + runID

	stage("teardown any prior containers for run %s", runID)
	Teardown(runID)
	dockerx.NetworkCreate(network)

	stage("TLS certs")
	ledgerNames := make([]string, len(ncs))
	for i := range ncs {
		ledgerNames[i] = ncs[i].Name("ledger")
	}
	if err := MintCerts(lay.Certs, ledgerNames); err != nil {
		return nil, fmt.Errorf("mint certs: %w", err)
	}
	okf("CA + server + client minted (server SAN covers %d ledger name(s))", len(ledgerNames))

	in := Infra{prefix: prefix, network: network, images: images, pgMaxConns: spec.Tuning.PGMaxConns}
	stage("infra — postgres + seaweedfs")
	if err := in.Up(); err != nil {
		return nil, fmt.Errorf("infra: %w", err)
	}
	okf("postgres + seaweedfs up (per-network buckets created at ledger bring-up)")

	manifest := &runstore.Manifest{
		ID: runID, Preset: spec.Name, Network: network, Admission: spec.Tuning.Admission,
		WALRetentionBuffer: ncs[0].Tuning.WALRetentionBuffer, // env-overridden in DeriveNetConfigs; gates verify.walgc
	}
	// ── PASS 1: fixtures for EVERY network ─────────────────────────────
	// All bootstraps must exist before any JN starts: in a multi-network run
	// each JN's foreign peer_logs (FED-1 #107) are rendered from the SIBLING
	// networks' minted constitutions.
	for i := range ncs {
		nc := &ncs[i]
		fixturesDir := lay.Fixtures
		if !nc.Single {
			fixturesDir = filepath.Join(lay.Fixtures, nc.Spec.Name)
		}

		stage("network %q — fixtures (%d witnesses) + signer/auditor keys", nc.Spec.Name, nc.Spec.Witnesses)
		// Mint the ledger gossip-originator key AND the auditor gossip key FIRST, so
		// both did:keys can be declared as genesis auditors in the bootstrap. The
		// always-on auditor-scope gate recognizes them: the ledger's monitor and the
		// auditor's scanner both publish claim-class findings (equivocation, etc.).
		if err := MintSignerKey(fixturesDir, images.Ledger, uidGID()); err != nil {
			return nil, fmt.Errorf("network %s: ledger signer key: %w", nc.Spec.Name, err)
		}
		ledgerDID, err := ledgerDIDFromSignerKey(filepath.Join(fixturesDir, ledgerSignerKeyFile))
		if err != nil {
			return nil, fmt.Errorf("network %s: derive ledger did:key: %w", nc.Spec.Name, err)
		}
		auditorDID, err := MintAuditorGossipKey(fixturesDir)
		if err != nil {
			return nil, fmt.Errorf("network %s: mint auditor gossip key: %w", nc.Spec.Name, err)
		}
		// Findings URL is fixture-only: the gate keys on DID + scope, not the URL,
		// but the SDK requires every auditor registration to carry a valid one.
		findingsURL := "https://" + nc.Name("ledger") + ":8080/v1/gossip"
		did, err := MintBootstrap(fixturesDir, images.Witness, nc.Spec.Witnesses, nc.LogDIDSeed, uidGID(),
			[]string{ledgerDID, auditorDID}, findingsURL)
		if err != nil {
			return nil, fmt.Errorf("network %s: %w", nc.Spec.Name, err)
		}
		nc.LogDID = did
		okf("bootstrap log DID: %s (genesis auditors: ledger + auditor)", did)
	}

	// ── PASS 2: services per network ────────────────────────────────────
	for i := range ncs {
		nc := &ncs[i]
		fixturesDir := lay.Fixtures
		if !nc.Single {
			fixturesDir = filepath.Join(lay.Fixtures, nc.Spec.Name)
		}

		if nc.DB != pgDBDefault {
			if err := in.EnsureDB(nc.DB); err != nil {
				return nil, err
			}
		}

		stage("network %q — witnesses", nc.Spec.Name)
		if err := UpWitnessFleet(*nc, fixturesDir, images.Witness); err != nil {
			return nil, err
		}
		okf("%d witnesses ready (K=%d)", nc.Spec.Witnesses, nc.Spec.QuorumK)

		// Each network's ledger writes its fixed-name objects (the cosigned-checkpoint
		// horizon) to its OWN bucket, so no network can clobber another's horizon.
		in.CreateBucket(nc.Bucket)

		stage("network %q — ledger on :%d (bucket %s)", nc.Spec.Name, nc.LedgerPort, nc.Bucket)
		if err := UpLedger(*nc, in, fixturesDir, lay.Certs, images.Ledger); err != nil {
			return nil, err
		}
		okf("ledger /healthz == ok")

		// Optional PG-off read front (the federation.proof.pgoff arm). Same image's
		// /ledger-reader entrypoint, same shared object store + server cert, Postgres
		// pointed at a dead host — it reconstructs proofs from the object store the
		// writer ships tiles to. Opt-in (E2E_READER=1) so the default stack stays lean.
		readerPort := 0
		if readerEnabled() {
			stage("network %q — PG-off read front on :%d (object-store-backed)", nc.Spec.Name, nc.ReaderPort)
			if err := UpReader(*nc, in, fixturesDir, lay.Certs, images.Ledger); err != nil {
				return nil, fmt.Errorf("network %s read front: %w", nc.Spec.Name, err)
			}
			readerPort = nc.ReaderPort
			okf("read front /healthz == ok (Postgres off)")
		}

		stage("network %q — seed (genesis-seed → fleet cosigns the head)", nc.Spec.Name)
		if err := SeedOnUp(in, *nc, fixturesDir, lay.Certs, images.Ledger); err != nil {
			return nil, fmt.Errorf("network %s: %w", nc.Spec.Name, err)
		}
		okf("cosigned tree head (size>=1, sigs>=%d)", nc.Spec.QuorumK)

		for idx := 1; idx <= nc.Spec.Auditors; idx++ {
			if err := in.EnsureDB(nc.GossipDB(idx)); err != nil {
				return nil, err
			}
		}
		if nc.Spec.Auditors > 0 {
			stage("network %q — %d auditors", nc.Spec.Name, nc.Spec.Auditors)
			if err := UpAuditors(*nc, in, fixturesDir, lay.Certs, images.Auditor); err != nil {
				return nil, err
			}
			okf("auditors /readyz == 200")
		}

		jnPort := 0
		if nc.Spec.HasJN {
			// FED-1 #107: this JN's foreign trust roots = every sibling
			// network's minted constitution (chain ROOT only; eras arrive as
			// verified rotation findings over the peer auditor's feed).
			var peerSeeds []PeerSeed
			for j := range ncs {
				if j == i {
					continue
				}
				peerFx := lay.Fixtures
				if !ncs[j].Single {
					peerFx = filepath.Join(lay.Fixtures, ncs[j].Spec.Name)
				}
				peerBoot, perr := bootstrap.Load(filepath.Join(peerFx, "network-bootstrap.json"))
				if perr != nil {
					return nil, fmt.Errorf("network %s: load peer %s bootstrap: %w", nc.Spec.Name, ncs[j].Spec.Name, perr)
				}
				seed, perr := PeerSeedFor(ncs[j], peerFx, fmt.Sprintf("%x", peerBoot.NetworkID))
				if perr != nil {
					return nil, fmt.Errorf("network %s: peer seed for %s: %w", nc.Spec.Name, ncs[j].Spec.Name, perr)
				}
				peerSeeds = append(peerSeeds, seed)
			}
			if len(peerSeeds) > 0 {
				if err := WriteJNPeerConfig(fixturesDir, peerSeeds); err != nil {
					return nil, fmt.Errorf("network %s: write jn peer config: %w", nc.Spec.Name, err)
				}
				okf("FED-1 peer_logs rendered: %d foreign trust roots", len(peerSeeds))
			}
			stage("network %q — JN enforcer on :%d", nc.Spec.Name, nc.JNPort)
			if err := UpJN(*nc, lay.Certs, fixturesDir, images.JN); err != nil {
				if !jnBestEffort() {
					return nil, err
				}
				fmt.Printf("  ⚠ JN did NOT come up (%v) — continuing (E2E_JN_BEST_EFFORT=1); the open ledger/auditor/tools path is unaffected. A stale JN image (no open-HTTPS JN→ledger leg) is the usual cause — build it from this branch.\n", err)
			} else {
				jnPort = nc.JNPort
				okf("JN mTLS /readyz == 200")
			}
		}

		aggPort := 0
		if nc.Spec.HasAggregator {
			// Best-effort bring-up: a failure is logged loudly but does NOT abort the
			// stack. Verified in the JN sources: the network-api makes no call to the
			// aggregator (no API_AGGREGATOR_* config) and its /readyz gates only on the
			// ledger (buildReadyzChecks), so admission/enforcement/proof-serving stay
			// fully usable with an absent/stale projection. `run verify.aggregator`
			// asserts the read side when you need it green.
			var aggErr error
			if aggErr = in.EnsureDB(nc.AggDB); aggErr == nil {
				stage("network %q — aggregator on :%d (non-core read-projection)", nc.Spec.Name, nc.AggregatorPort)
				aggErr = UpAggregator(*nc, in, lay.Certs, images.Aggregator)
			}
			if aggErr != nil {
				fmt.Printf("  ⚠ aggregator did NOT come up (%v) — continuing; JN core is unaffected, queries degraded\n", aggErr)
			} else {
				aggPort = nc.AggregatorPort
				okf("aggregator /readyz == 200")
			}
		}

		manifest.Networks = append(manifest.Networks, runstore.NetworkManifest{
			Name: nc.Spec.Name, LogDID: nc.LogDID, QuorumK: nc.Spec.QuorumK,
			LedgerName: nc.Name("ledger"), LedgerPort: nc.LedgerPort, ReaderPort: readerPort, JNPort: jnPort,
			DB: nc.DB, Bucket: nc.Bucket,
			AggregatorPort: aggPort, AuditorPorts: nc.AuditorPorts,
		})
	}

	if err := lay.SaveManifest(manifest); err != nil {
		return nil, fmt.Errorf("persist manifest: %w", err)
	}
	return manifest, nil
}

// Teardown force-removes every container for a run id and removes its network
// (best-effort).
func Teardown(runID string) {
	prefix := "baseproof-" + runID
	if ids := dockerx.PSByPrefix(prefix); len(ids) > 0 {
		dockerx.Remove(ids...)
	}
	dockerx.NetworkRemove(prefix)
}

// Wipe tears the stack down and removes its run-store state directory.
func Wipe(runID string) error {
	Teardown(runID)
	lay, err := runstore.New(runID)
	if err != nil {
		return err
	}
	return lay.Remove()
}

// LedgerHealthy probes a network's ledger /healthz over its published host port
// using open HTTPS (certsDir holds the run CA the probe pins; no client cert).
func LedgerHealthy(n runstore.NetworkManifest, certsDir string) bool {
	return ledgerBody(certsDir, fmt.Sprintf("https://localhost:%d/healthz", n.LedgerPort)) == "ok"
}
