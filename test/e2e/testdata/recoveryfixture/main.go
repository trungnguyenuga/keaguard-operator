// recoveryfixture is a cluster-free executable for checking pinned Ginkgo
// cleanup ordering and interruption behavior. Its short deadlines are fixture
// only; the real M2 suite keeps the reviewed 44 minute budget.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

type fixtureT struct{ failed bool }

func (t *fixtureT) Fail() { t.failed = true }

var mode = os.Getenv("M2_FIXTURE_MODE")
var dir = os.Getenv("M2_FIXTURE_DIR")

func event(name string) { fmt.Printf("M2-EVENT %s\n", name) }

func state(name, value string) {
	if err := os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0600); err != nil {
		panic(err)
	}
}

func critical(ctx SpecContext) {
	event("critical")
	if mode == "critical-timeout" || mode == "critical-interrupt" || mode == "repeated-interrupt" {
		state("diagnostics", "skipped-recovery-incomplete")
		<-ctx.Done()
		return
	}
	state("recovery-restored", "verified")
	if err := os.Remove(filepath.Join(dir, "recovery-pending")); err != nil {
		panic(err)
	}
	event("sealed")
}

func diagnostic(ctx SpecContext) {
	event("diagnostic")
	state("diagnostics", "started")
	switch mode {
	case "diagnostic-block":
		bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		child := exec.CommandContext(bounded, os.Args[0], "diagnostic-child")
		child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		child.WaitDelay = 100 * time.Millisecond
		child.Cancel = func() error {
			if child.Process == nil {
				return os.ErrProcessDone
			}
			err := syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
			if err == syscall.ESRCH {
				return os.ErrProcessDone
			}
			return err
		}
		if err := child.Run(); err == nil {
			panic("blocked diagnostic unexpectedly completed")
		}
		state("diagnostics", "failed")
		Fail("diagnostic subprocess did not complete")
	case "diagnostic-interrupt":
		<-ctx.Done()
		state("diagnostics", "interrupted")
	default:
		state("diagnostics", "ok")
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "diagnostic-child" {
		time.Sleep(10 * time.Second)
		return
	}
	if mode == "" || dir == "" {
		fmt.Fprintln(os.Stderr, "fixture mode and private directory required")
		os.Exit(2)
	}
	if mode == "legacy" {
		AfterEach(func(ctx SpecContext) {
			event("legacy-after")
			<-ctx.Done()
		}, NodeTimeout(180*time.Millisecond), GracePeriod(100*time.Millisecond))
	}
	BeforeSuite(func(_ SpecContext) {
		DeferCleanup(func(_ SpecContext) { event("suite-cancel") }, NodeTimeout(100*time.Millisecond), GracePeriod(100*time.Millisecond))
	}, NodeTimeout(200*time.Millisecond), GracePeriod(100*time.Millisecond))
	Describe("recovery order", Ordered, func() {
		BeforeEach(func(_ SpecContext) {
			if _, err := os.Stat(filepath.Join(dir, "recovery-pending")); err == nil {
				event("guard-refused")
				AbortSuite("unproved recovery from an earlier invocation")
			}
			if data, err := os.ReadFile(filepath.Join(dir, "diagnostics")); err == nil && string(data) != "ok\n" {
				event("guard-refused")
				AbortSuite("incomplete diagnostics from an earlier invocation")
			}
		}, NodeTimeout(200*time.Millisecond), GracePeriod(100*time.Millisecond))
		It("runs the invasive case", func(ctx SpecContext) {
			DeferCleanup(func(cleanupCtx SpecContext) {
				critical(cleanupCtx)
				if cleanupCtx.Err() != nil {
					return
				}
				diagnostic(cleanupCtx)
			}, NodeTimeout(2*time.Second), GracePeriod(100*time.Millisecond))
			state("recovery-pending", "pending")
			state("diagnostics", "not-started")
			event("body")
			switch mode {
			case "legacy":
				Fail("legacy body failure")
			case "body-timeout":
				<-ctx.Done()
			}
		}, NodeTimeout(200*time.Millisecond), SpecTimeout(4*time.Second), GracePeriod(100*time.Millisecond))
		It("refuses a second invasive case after failure", func(_ SpecContext) {
			if _, err := os.Stat(filepath.Join(dir, "recovery-pending")); err == nil {
				AbortSuite("unproved recovery before second case")
			}
			data, err := os.ReadFile(filepath.Join(dir, "diagnostics"))
			if err != nil || string(data) != "ok\n" {
				AbortSuite("incomplete diagnostics before second case")
			}
			event("sentinel")
		}, NodeTimeout(200*time.Millisecond), GracePeriod(100*time.Millisecond))
	})
	cfg, reporter := GinkgoConfiguration()
	cfg.FailOnEmpty = true
	cfg.FailFast = true
	cfg.Timeout = 5 * time.Second
	cfg.GracePeriod = 100 * time.Millisecond
	t := &fixtureT{}
	if !RunSpecs(t, "M2 cluster-free recovery timing fixture", cfg, reporter) || t.failed {
		os.Exit(1)
	}
}
