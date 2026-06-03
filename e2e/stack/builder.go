package stack

import (
	"fmt"
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

	stage("mTLS certs")
	if err := MintCerts(lay.Certs); err != nil {
		return nil, fmt.Errorf("mint certs: %w", err)
	}
	okf("CA + server + client minted")

	in := Infra{prefix: prefix, network: network, images: images, pgMaxConns: spec.Tuning.PGMaxConns}
	stage("infra — postgres + seaweedfs")
	if err := in.Up(); err != nil {
		return nil, fmt.Errorf("infra: %w", err)
	}
	okf("postgres + seaweedfs up (bucket %s)", bucket)

	manifest := &runstore.Manifest{ID: runID, Preset: spec.Name, Network: network, Admission: spec.Tuning.Admission}
	for i := range ncs {
		nc := &ncs[i]
		fixturesDir := lay.Fixtures
		if !nc.Single {
			fixturesDir = filepath.Join(lay.Fixtures, nc.Spec.Name)
		}

		stage("network %q — fixtures (%d witnesses) + signer key", nc.Spec.Name, nc.Spec.Witnesses)
		did, err := MintBootstrap(fixturesDir, images.Witness, nc.Spec.Witnesses, nc.LogDIDSeed, uidGID())
		if err != nil {
			return nil, fmt.Errorf("network %s: %w", nc.Spec.Name, err)
		}
		nc.LogDID = did
		if err := MintSignerKey(fixturesDir, images.Ledger, uidGID()); err != nil {
			return nil, fmt.Errorf("network %s: %w", nc.Spec.Name, err)
		}
		okf("bootstrap log DID: %s", did)

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

		stage("network %q — ledger on :%d", nc.Spec.Name, nc.LedgerPort)
		if err := UpLedger(*nc, in, fixturesDir, images.Ledger); err != nil {
			return nil, err
		}
		okf("ledger /healthz == ok")

		stage("network %q — seed (genesis-seed → fleet cosigns the head)", nc.Spec.Name)
		if err := SeedOnUp(in, *nc, fixturesDir, images.Ledger); err != nil {
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
			if err := UpAuditors(*nc, in, fixturesDir, images.Auditor); err != nil {
				return nil, err
			}
			okf("auditors /readyz == 200")
		}

		jnPort := 0
		if nc.Spec.HasJN {
			stage("network %q — JN enforcer on :%d", nc.Spec.Name, nc.JNPort)
			if err := UpJN(*nc, lay.Certs, fixturesDir, images.JN); err != nil {
				return nil, err
			}
			jnPort = nc.JNPort
			okf("JN mTLS /readyz == 200")
		}

		manifest.Networks = append(manifest.Networks, runstore.NetworkManifest{
			Name: nc.Spec.Name, LogDID: did, QuorumK: nc.Spec.QuorumK,
			LedgerName: nc.Name("ledger"), LedgerPort: nc.LedgerPort, JNPort: jnPort,
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

// LedgerHealthy probes a network's ledger /healthz over its published host port.
func LedgerHealthy(n runstore.NetworkManifest) bool {
	return httpBody(fmt.Sprintf("http://localhost:%d/healthz", n.LedgerPort)) == "ok"
}
