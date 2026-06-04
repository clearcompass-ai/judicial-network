package dockerx

import (
	"strings"
	"testing"
)

func joined(a []string) string { return strings.Join(a, " ") }

func TestRunArgv_DetachedFull(t *testing.T) {
	s := RunSpec{
		Name: "e2e-x-ledger", Network: "e2e-x", Image: "img:1", Detached: true,
		User: "1000:1000", Entrypoint: "/ledger",
		Ports:     []Port{{Host: 8080, Container: 8080}},
		Mounts:    []Mount{{Host: "/run/x/fixtures", Container: "/run/fixtures"}},
		Env:       map[string]string{"B": "2", "A": "1"},
		ImageArgs: []string{"-flag"},
	}
	got := joined(runArgv(s))
	for _, want := range []string{
		"docker run -d --name e2e-x-ledger --network e2e-x",
		"--user 1000:1000", "--entrypoint /ledger",
		"-p 8080:8080", "-v /run/x/fixtures:/run/fixtures",
		"-e A=1 -e B=2", // sorted for determinism
		"img:1 -flag",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("argv missing %q\n got: %s", want, got)
		}
	}
	// env ordering is deterministic (A before B) regardless of map iteration.
	if strings.Index(got, "-e A=1") > strings.Index(got, "-e B=2") {
		t.Fatalf("env not sorted: %s", got)
	}
}

func TestRunArgv_EphemeralRemove(t *testing.T) {
	s := RunSpec{Network: "e2e-x", Image: "img:1", Remove: true, Entrypoint: "/backfill",
		ImageArgs: []string{"-n", "30000"}}
	got := joined(runArgv(s))
	if !strings.Contains(got, "docker run --rm") {
		t.Fatalf("missing --rm: %s", got)
	}
	if strings.Contains(got, "--name") {
		t.Fatalf("ephemeral without a name should not emit --name: %s", got)
	}
	if !strings.HasSuffix(got, "img:1 -backfill_args") && !strings.Contains(got, "img:1 -n 30000") {
		t.Fatalf("image args misplaced: %s", got)
	}
}

func TestBuildArgv_FullWithSecretAndArgs(t *testing.T) {
	got := joined(buildArgv(BuildSpec{
		Tag:        "ghcr.io/clearcompass-ai/judicial-network:latest",
		Dockerfile: "/repo/deployment/local/Dockerfile.network-api",
		Context:    "/repo",
		BuildArgs:  map[string]string{"VERSION": "v1.2.3", "FOO": "bar"},
		Secrets:    []string{"id=ca_bundle,src=/etc/ssl/certs/ca-certificates.crt"},
	}))
	for _, want := range []string{
		"docker build -f /repo/deployment/local/Dockerfile.network-api -t ghcr.io/clearcompass-ai/judicial-network:latest",
		"--secret id=ca_bundle,src=/etc/ssl/certs/ca-certificates.crt",
		"--build-arg FOO=bar --build-arg VERSION=v1.2.3", // build args sorted for determinism
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("build argv missing %q\n got: %s", want, got)
		}
	}
	// The context dir is the final positional argument.
	if !strings.HasSuffix(got, " /repo") {
		t.Fatalf("context must be the last arg: %s", got)
	}
}

func TestBuildArgv_MinimalNoSecret(t *testing.T) {
	got := joined(buildArgv(BuildSpec{Tag: "img:e2e", Dockerfile: "Dockerfile", Context: "."}))
	if got != "docker build -f Dockerfile -t img:e2e ." {
		t.Fatalf("minimal build argv = %q", got)
	}
	if strings.Contains(got, "--secret") || strings.Contains(got, "--build-arg") {
		t.Fatalf("no secrets/args expected: %s", got)
	}
}

func TestExecArgv(t *testing.T) {
	if got := joined(execArgv("e2e-x-postgres", []string{"createdb", "-U", "baseproof", "g1"}, false)); got !=
		"docker exec e2e-x-postgres createdb -U baseproof g1" {
		t.Fatalf("execArgv = %q", got)
	}
	if got := joined(execArgv("c", []string{"ls"}, true)); got != "docker exec -u 0 c ls" {
		t.Fatalf("root execArgv = %q", got)
	}
}
