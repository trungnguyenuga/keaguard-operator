package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitM2DockerBuildIsolation(t *testing.T) {
	const script = "../../hack/m2-docker-build-env.sh"
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	accept := filepath.Join(root, "docker-config")
	build := filepath.Join(root, "docker-build-config")
	if err := os.Mkdir(accept, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(task, acceptance, buildConfig, selectedConfig string, extraEnv ...string) (string, error) {
		t.Helper()
		cmd := exec.Command("bash", script, task, acceptance, buildConfig, "--", "sh", "-c", `touch "$DOCKER_CONFIG/build-metadata"; printf 'EXECUTED:%s' "$DOCKER_CONFIG"`)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=/nonexistent", "LC_ALL=C", "DOCKER_CONFIG=" + selectedConfig}, extraEnv...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := run(root, accept, build, accept)
	if err != nil || out != "EXECUTED:"+build {
		t.Fatalf("isolated build did not execute in private build config: err=%v output=%q", err, out)
	}
	if _, err := os.Stat(filepath.Join(build, "build-metadata")); err != nil {
		t.Fatalf("fake build metadata missing from build config: %v", err)
	}
	entries, err := os.ReadDir(accept)
	if err != nil || len(entries) != 0 {
		t.Fatalf("acceptance config was contaminated: entries=%v err=%v", entries, err)
	}
	if info, err := os.Lstat(build); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatalf("build config not a private directory: info=%v err=%v", info, err)
	}

	refuse := func(name, task, acceptance, buildConfig, selectedConfig, message string, extraEnv ...string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			out, err := run(task, acceptance, buildConfig, selectedConfig, extraEnv...)
			if err == nil || !strings.Contains(out, message) || strings.Contains(out, "EXECUTED:") {
				t.Fatalf("unsafe build environment was not refused before command: err=%v output=%q", err, out)
			}
		})
	}
	refuse("shared acceptance and build directory", root, accept, accept, accept, "build and acceptance Docker configs must differ")
	refuse("global Docker config inheritance", root, accept, build, filepath.Join(root, "global"), "DOCKER_CONFIG must select the acceptance directory")
	refuse("auth environment inheritance", root, accept, build, accept, "DOCKER_AUTH_CONFIG is not allowed", `DOCKER_AUTH_CONFIG={"auths":{}}`)

	if err := os.WriteFile(filepath.Join(build, "config.json"), []byte(`{"auths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	refuse("credential file inheritance", root, accept, build, accept, "credential config is not allowed")
	if err := os.Remove(filepath.Join(build, "config.json")); err != nil {
		t.Fatal(err)
	}

	linkedRoot := t.TempDir()
	if err := os.Chmod(linkedRoot, 0700); err != nil {
		t.Fatal(err)
	}
	linkedAccept := filepath.Join(linkedRoot, "docker-config")
	if err := os.Mkdir(linkedAccept, 0700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(linkedRoot, "other")
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(linkedRoot, "docker-build-config")
	if err := os.Symlink(other, linked); err != nil {
		t.Fatal(err)
	}
	refuse("symlink build config", linkedRoot, linkedAccept, linked, linkedAccept, "build Docker config must be a non-symlink")
	linkedEntry := filepath.Join(build, "linked-entry")
	if err := os.Symlink(other, linkedEntry); err != nil {
		t.Fatal(err)
	}
	refuse("symlink within build config", root, accept, build, accept, "build Docker config contains a symlink")
	if err := os.Remove(linkedEntry); err != nil {
		t.Fatal(err)
	}

	if os.Getuid() != 0 {
		refuse("foreign owner", "/tmp", "/tmp/docker-config", "/tmp/docker-build-config", "/tmp/docker-config", "task directory has foreign ownership")
	}
}

func TestUnitM2DockerBuildMakeIsolation(t *testing.T) {
	cmd := exec.Command("make", "--no-print-directory", "-n", "docker-build", "IMG=keaguard-operator:m2-fingerprint", "BUILD_IID_FILE=/tmp/keaguard-m2-acceptance/manager-image.iid")
	cmd.Dir = "../.."
	cmd.Env = makeTestEnv("GOTOOLCHAIN=local", "DOCKER_CONFIG=/tmp/keaguard-m2-acceptance/docker-config")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("M2 Docker build dry run: %v\n%s", err, out)
	}
	line := "bash hack/m2-docker-build-env.sh /tmp/keaguard-m2-acceptance /tmp/keaguard-m2-acceptance/docker-config /tmp/keaguard-m2-acceptance/docker-build-config -- docker build --platform=linux/amd64 --iidfile /tmp/keaguard-m2-acceptance/manager-image.iid"
	if !strings.Contains(string(out), line) {
		t.Fatalf("fingerprinted M2 build does not execute through isolated Docker config: %s", out)
	}
	cmd = exec.Command("make", "--no-print-directory", "-n", "docker-build", "IMG=keaguard-operator:m1-test")
	cmd.Dir = "../.."
	cmd.Env = makeTestEnv("GOTOOLCHAIN=local")
	out, err = cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "m2-docker-build-env.sh") {
		t.Fatalf("ordinary M1 Docker build changed: err=%v output=%s", err, out)
	}
}
