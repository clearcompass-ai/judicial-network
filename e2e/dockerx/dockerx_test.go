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

func TestExecArgv(t *testing.T) {
	if got := joined(execArgv("e2e-x-postgres", []string{"createdb", "-U", "baseproof", "g1"}, false)); got !=
		"docker exec e2e-x-postgres createdb -U baseproof g1" {
		t.Fatalf("execArgv = %q", got)
	}
	if got := joined(execArgv("c", []string{"ls"}, true)); got != "docker exec -u 0 c ls" {
		t.Fatalf("root execArgv = %q", got)
	}
}
