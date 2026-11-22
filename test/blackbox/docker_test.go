package blackbox

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Docker tests run only with GW_DOCKER_TESTS=1 (they build the image).
func dockerOrSkip(t *testing.T) {
	if os.Getenv("GW_DOCKER_TESTS") != "1" {
		t.Skip("set GW_DOCKER_TESTS=1 to build and test the Docker image")
	}
}
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

const image = "mcp-gateway:test"

// spec: DEP-006
func TestDockerImageHardening(t *testing.T) {
	dockerOrSkip(t)
	run(t, "docker", "build", "-t", image, "../..")
	if u := run(t, "docker", "image", "inspect", "-f", "{{.Config.User}}", image); u == "" || u == "0" || u == "root" || strings.HasPrefix(u, "0:") {
		t.Fatalf("image runs as %q, want a non-root user", u)
	}
	if v := run(t, "docker", "image", "inspect", "-f", "{{json .Config.Volumes}}", image); !strings.Contains(v, "/data") {
		t.Fatalf("data volume: %s", v)
	}
	for _, sh := range []string{"/bin/sh", "/bin/bash", "/sbin/apk", "/usr/bin/apt"} {
		if out, err := exec.Command("docker", "run", "--rm", "--entrypoint", sh, image, "-c", "true").CombinedOutput(); err == nil {
			t.Fatalf("final image contains %s: %s", sh, out)
		}
	}
	if out := run(t, "docker", "run", "--rm", image, "version"); !strings.HasPrefix(out, "mcp-gateway ") {
		t.Fatalf("version: %s", out)
	}
}

// spec: DEP-007, DEP-008
func TestDockerAllInOneServes(t *testing.T) {
	dockerOrSkip(t)
	run(t, "docker", "build", "-t", image, "../..")
	key := strings.TrimSpace(output(binPath, "keygen", "admin"))
	port := strings.Split(freePort(), ":")[1]
	id := run(t, "docker", "run", "-d", "--rm", "-p", "127.0.0.1:"+port+":8787",
		"-e", "GW_PUBLIC_URL=http://127.0.0.1:"+port, "-e", "GW_KEY_PROVIDER=env",
		"-e", "GW_MASTER_KEY="+output(binPath, "keygen", "master"), "-e", "GW_BOOTSTRAP_ADMIN_KEY="+key,
		"--read-only", "--cap-drop", "ALL", image)
	defer exec.Command("docker", "rm", "-f", id).Run()
	if err := waitReady("http://127.0.0.1:"+port, 30*time.Second); err != nil {
		logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
		t.Fatalf("%v\n%s", err, logs)
	}
}
