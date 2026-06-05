// Package dockerx is the only layer that shells out to the `docker` CLI.
//
// The argv for each command is built by a pure function (testable without a
// daemon); thin wrappers execute it, so the bring-up logic above it stays
// docker-implementation-agnostic.
package dockerx

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Mount is a -v host:container bind.
type Mount struct{ Host, Container string }

// Port is a -p host:container publish.
type Port struct{ Host, Container int }

// RunSpec describes a `docker run` invocation.
type RunSpec struct {
	Name       string // --name (empty ⇒ none)
	Network    string // --network
	Image      string
	Env        map[string]string
	Ports      []Port
	Mounts     []Mount
	User       string // --user
	Entrypoint string // --entrypoint
	ImageArgs  []string
	Detached   bool // -d (else --rm foreground, captured)
	Remove     bool // --rm
}

// Result is a captured command outcome.
type Result struct {
	Code   int
	Stdout string
	Stderr string
}

// OK reports a zero exit.
func (r Result) OK() bool { return r.Code == 0 }

func run(argv []string) Result {
	cmd := exec.Command(argv[0], argv[1:]...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
			errb.WriteString(err.Error())
		}
	}
	return Result{Code: code, Stdout: out.String(), Stderr: errb.String()}
}

// runArgv builds the argv for a `docker run`. Env keys are sorted for determinism.
func runArgv(s RunSpec) []string {
	a := []string{"docker", "run"}
	if s.Detached {
		a = append(a, "-d")
	}
	if s.Remove {
		a = append(a, "--rm")
	}
	if s.Name != "" {
		a = append(a, "--name", s.Name)
	}
	if s.Network != "" {
		a = append(a, "--network", s.Network)
	}
	if s.User != "" {
		a = append(a, "--user", s.User)
	}
	if s.Entrypoint != "" {
		a = append(a, "--entrypoint", s.Entrypoint)
	}
	for _, p := range s.Ports {
		a = append(a, "-p", fmt.Sprintf("%d:%d", p.Host, p.Container))
	}
	for _, m := range s.Mounts {
		a = append(a, "-v", m.Host+":"+m.Container)
	}
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a = append(a, "-e", k+"="+s.Env[k])
	}
	a = append(a, s.Image)
	a = append(a, s.ImageArgs...)
	return a
}

// Run executes a RunSpec.
func Run(s RunSpec) Result { return run(runArgv(s)) }

func execArgv(name string, argv []string, root bool) []string {
	a := []string{"docker", "exec"}
	if root {
		a = append(a, "-u", "0")
	}
	a = append(a, name)
	return append(a, argv...)
}

// Exec runs `docker exec` against a container.
func Exec(name string, argv []string, root bool) Result { return run(execArgv(name, argv, root)) }

// DaemonOK reports whether the docker daemon is reachable.
func DaemonOK() bool { return run([]string{"docker", "info"}).OK() }

// ImagePresent reports whether an image exists locally.
func ImagePresent(img string) bool { return run([]string{"docker", "image", "inspect", img}).OK() }

// Pull pulls an image.
func Pull(img string) Result { return run([]string{"docker", "pull", img}) }

// BuildSpec describes a `docker build`. Used to build the JN-owned images
// (network-api, aggregator) from the LOCAL working tree so the e2e exercises the
// code under test, never a stale ghcr-published image.
type BuildSpec struct {
	Tag        string            // -t
	Dockerfile string            // -f (absolute or context-relative)
	Context    string            // the build context directory (the repo root)
	BuildArgs  map[string]string // --build-arg
	Secrets    []string          // --secret entries, e.g. "id=ca_bundle,src=/path"
}

// buildArgv builds the argv for a `docker build`. Build args are sorted for
// determinism.
func buildArgv(s BuildSpec) []string {
	a := []string{"docker", "build", "-f", s.Dockerfile, "-t", s.Tag}
	for _, sec := range s.Secrets {
		a = append(a, "--secret", sec)
	}
	keys := make([]string, 0, len(s.BuildArgs))
	for k := range s.BuildArgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a = append(a, "--build-arg", k+"="+s.BuildArgs[k])
	}
	return append(a, s.Context)
}

// Build runs `docker build`, STREAMING progress to stdout/stderr (a multi-stage Go
// build is slow and the operator wants live output). BuildKit is forced on so the
// Dockerfiles' --mount=type=secret / type=cache directives work.
func Build(s BuildSpec) error {
	argv := buildArgv(s)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=1")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// NetworkCreate / NetworkRemove manage the run's docker network (errors ignored —
// create is idempotent-ish, remove is best-effort).
func NetworkCreate(net string) { _ = run([]string{"docker", "network", "create", net}) }
func NetworkRemove(net string) { _ = run([]string{"docker", "network", "rm", net}) }

// Remove force-removes containers (best-effort).
func Remove(names ...string) {
	if len(names) == 0 {
		return
	}
	_ = run(append([]string{"docker", "rm", "-f", "-v"}, names...))
}

// PSByPrefix returns container ids whose name matches a prefix.
func PSByPrefix(prefix string) []string {
	r := run([]string{"docker", "ps", "-aq", "--filter", "name=" + prefix})
	return strings.Fields(r.Stdout)
}

// Wait blocks until a container exits, returning its exit code as a string.
func Wait(name string) string {
	return strings.TrimSpace(run([]string{"docker", "wait", name}).Stdout)
}

// LogsFollow streams a container's logs to our stdout/stderr until it exits — live
// progress for long steps (e.g. backfill's count/%/rate/ETA).
func LogsFollow(name string) error {
	cmd := exec.Command("docker", "logs", "-f", name)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// Logs returns a container's combined stdout+stderr.
func Logs(name string) string {
	r := run([]string{"docker", "logs", name})
	return r.Stdout + r.Stderr
}

// LogCount counts occurrences of substr in a container's logs.
func LogCount(name, substr string) int { return strings.Count(Logs(name), substr) }

// State returns "{status} exit={code}" for a container.
func State(name string) string {
	return strings.TrimSpace(run([]string{
		"docker", "inspect", "-f", "{{.State.Status}} exit={{.State.ExitCode}}", name,
	}).Stdout)
}

// ContainerIP resolves a container's IP on its network.
func ContainerIP(name string) (string, error) {
	r := run([]string{
		"docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name,
	})
	ip := strings.TrimSpace(r.Stdout)
	if ip == "" {
		return "", fmt.Errorf("could not resolve IP for container %s", name)
	}
	return ip, nil
}

// PGQuery runs a -tAc psql query inside the postgres container; ok=false on error.
func PGQuery(pg, user, db, sql string) (string, bool) {
	r := run([]string{"docker", "exec", pg, "psql", "-U", user, "-d", db, "-tAc", sql})
	if !r.OK() {
		return "", false
	}
	return strings.TrimSpace(r.Stdout), true
}
