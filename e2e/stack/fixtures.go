package stack

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/clearcompass-ai/judicial-network/e2e/dockerx"
)

// serverSAN builds the subjectAltName value for the SHARED server cert (the
// ledger AND the JN listener present it). It carries the host-side names
// (localhost / 127.0.0.1) for host probes hitting localhost:{port}, PLUS every
// ledger container DNS name — because in-network clients (the auditors, the JN,
// the aggregator, and the seed/backfill/audit tool containers) reach the ledger
// by its CONTAINER NAME over open HTTPS and verify the server cert against this
// SAN. A localhost-only SAN passes host probes but fails the in-network
// handshake on server-name verification.
func serverSAN(ledgerDNSNames []string) string {
	entries := []string{"DNS:localhost", "IP:127.0.0.1"}
	for _, n := range ledgerDNSNames {
		entries = append(entries, "DNS:"+n)
	}
	return strings.Join(entries, ",")
}

// MintCerts mints the stack TLS material (CA + server + client) into certsDir via
// openssl. The server cert's SAN covers localhost + every ledger container name
// in ledgerDNSNames (so open-HTTPS server-verify succeeds — see serverSAN). The
// client cert is for the JN's OWN mTLS listener (the ledger leg presents none);
// it carries the harness caller DID as a URI SAN.
func MintCerts(certsDir string, ledgerDNSNames []string) error {
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certsDir, "srv.ext"),
		[]byte("subjectAltName="+serverSAN(ledgerDNSNames)+"\nextendedKeyUsage=serverAuth\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(certsDir, "cli.ext"),
		[]byte("subjectAltName=URI:"+callerDID+"\nextendedKeyUsage=clientAuth\n"), 0o644); err != nil {
		return err
	}
	d := certsDir
	openssl := func(args ...string) error {
		if out, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("openssl %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	if err := openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", d+"/ca.key"); err != nil {
		return err
	}
	if err := openssl("req", "-x509", "-new", "-key", d+"/ca.key", "-sha256", "-days", "365",
		"-subj", "/CN="+caCN, "-out", d+"/ca.crt"); err != nil {
		return err
	}
	for _, who := range []struct{ name, ext, cn string }{
		{"server", "srv.ext", "localhost"},
		{"client", "cli.ext", callerDID},
	} {
		if err := openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", d+"/"+who.name+".key"); err != nil {
			return err
		}
		if err := openssl("req", "-new", "-key", d+"/"+who.name+".key", "-subj", "/CN="+who.cn, "-out", d+"/"+who.name+".csr"); err != nil {
			return err
		}
		if err := openssl("x509", "-req", "-in", d+"/"+who.name+".csr", "-CA", d+"/ca.crt", "-CAkey", d+"/ca.key",
			"-CAcreateserial", "-days", "365", "-sha256", "-extfile", d+"/"+who.ext, "-out", d+"/"+who.name+".crt"); err != nil {
			return err
		}
	}
	return nil
}

// MintBootstrap mints the per-network witness keys + gating-off genesis bootstrap
// into fixturesDir via the witness image's gen-fixtures, returning the bootstrap's
// log DID (exchange_did).
func MintBootstrap(fixturesDir, witnessImage string, witnesses int, logDIDSeed, uidGID string) (string, error) {
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		return "", err
	}
	r := dockerx.Run(dockerx.RunSpec{
		Network: "bridge", Image: witnessImage, Remove: true, Entrypoint: "/gen-fixtures", User: uidGID,
		Mounts: []dockerx.Mount{{Host: fixturesDir, Container: mntOut}},
		ImageArgs: []string{
			"-out-dir=" + mntOut, "-out-bootstrap=" + mntOut + "/network-bootstrap.json",
			fmt.Sprintf("-witnesses=%d", witnesses), "-log-did=" + logDIDSeed, "-network-name=" + netName,
		},
	})
	if !r.OK() {
		return "", fmt.Errorf("gen-fixtures failed: %s", tail(r.Stderr, 600))
	}
	return readExchangeDID(filepath.Join(fixturesDir, "network-bootstrap.json"))
}

// MintSignerKey mints a stable ledger operational signer key into fixturesDir via
// init-network -out-ledger-key (a persistent gossip-originator did:key across
// restarts).
func MintSignerKey(fixturesDir, ledgerImage, uidGID string) error {
	r := dockerx.Run(dockerx.RunSpec{
		Network: "bridge", Image: ledgerImage, Remove: true, Entrypoint: "/init-network", User: uidGID,
		Mounts: []dockerx.Mount{{Host: fixturesDir, Container: mntOut}},
		ImageArgs: []string{
			"-out-dir=" + mntOut + "/.ledger-key-gen",
			"-out-bootstrap=" + mntOut + "/.ledger-key-gen/bootstrap.json",
			"-out-ledger-key=" + mntOut + "/ledger-signer.key",
			"-witnesses=1", "-gating=off",
		},
	})
	_ = os.RemoveAll(filepath.Join(fixturesDir, ".ledger-key-gen"))
	if !r.OK() {
		return fmt.Errorf("init-network -out-ledger-key failed: %s", tail(r.Stderr, 600))
	}
	if _, err := os.Stat(filepath.Join(fixturesDir, "ledger-signer.key")); err != nil {
		return fmt.Errorf("init-network did not produce the ledger signer key (is the ledger image >= v1.18?)")
	}
	return nil
}

func readExchangeDID(bootstrapPath string) (string, error) {
	b, err := os.ReadFile(bootstrapPath)
	if err != nil {
		return "", fmt.Errorf("gen-fixtures did not produce %s: %w", bootstrapPath, err)
	}
	var doc struct {
		ExchangeDID string `json:"exchange_did"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", fmt.Errorf("parse bootstrap: %w", err)
	}
	if doc.ExchangeDID == "" {
		return "", fmt.Errorf("bootstrap has no exchange_did")
	}
	return doc.ExchangeDID, nil
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
