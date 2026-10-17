package main

import (
	"context"
	"flag"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

// These cases catch permissive validation, normalization, environment fallback,
// and accepting flags that enable infrastructure outside the M1 contract.
func TestUnitWatchNamespace(t *testing.T) {
	t.Setenv("WATCH_NAMESPACE", "environment-fallback")
	globalFlags := flag.CommandLine
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing", nil, ""},
		{"empty", []string{"--watch-namespace="}, ""},
		{"missing value", []string{"--watch-namespace"}, ""},
		{"whitespace", []string{"--watch-namespace= "}, ""},
		{"padded", []string{"--watch-namespace= valid "}, ""},
		{"uppercase", []string{"--watch-namespace=Valid"}, ""},
		{"underscore", []string{"--watch-namespace=invalid_name"}, ""},
		{"dot", []string{"--watch-namespace=invalid.name"}, ""},
		{"slash", []string{"--watch-namespace=a/b"}, ""},
		{"leading hyphen", []string{"--watch-namespace=-invalid"}, ""},
		{"trailing hyphen", []string{"--watch-namespace=invalid-"}, ""},
		{"too long", []string{"--watch-namespace=" + strings.Repeat("a", 64)}, ""},
		{"list", []string{"--watch-namespace=a,b"}, ""},
		{"wildcard", []string{"--watch-namespace=*"}, ""},
		{"unknown", []string{"--watch-namespace=valid", "--unknown"}, ""},
		{"leader election", []string{"--watch-namespace=valid", "--leader-elect"}, ""},
		{"metrics", []string{"--watch-namespace=valid", "--metrics-bind-address=:8080"}, ""},
		{"positional", []string{"--watch-namespace=valid", "extra"}, ""},
		{"positional first", []string{"extra", "--watch-namespace=valid"}, ""},
		{"valid", []string{"--watch-namespace=kea-lab-1"}, "kea-lab-1"},
		{"separate value", []string{"--watch-namespace", "kea-lab"}, "kea-lab"},
		{"explicit default", []string{"--watch-namespace=default"}, "default"},
		{"maximum length", []string{"--watch-namespace=" + strings.Repeat("a", 63)}, strings.Repeat("a", 63)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWatchNamespace(tc.args)
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatalf("invalid args returned namespace %q, error %v", got, err)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("got (%q, %v), want (%q, nil)", got, err, tc.want)
			}
		})
	}
	if flag.CommandLine != globalFlags || globalFlags.Lookup("watch-namespace") != nil {
		t.Fatal("parser mutated global flags")
	}
}

// Catch an empty namespace cache map, selectors that hide ownership loss, or
// accidentally enabled metrics/leader election in the manager boundary options.
func TestUnitManagerScope(t *testing.T) {
	s := runtime.NewScheme()
	for _, namespace := range []string{"kea-lab", "default"} {
		opts := managerOptionsForNamespace(namespace, s)
		if opts.Scheme != s || len(opts.Cache.DefaultNamespaces) != 1 {
			t.Fatalf("scheme or scoped cache missing: %+v", opts.Cache)
		}
		cfg, ok := opts.Cache.DefaultNamespaces[namespace]
		if !ok || cfg.LabelSelector != nil || cfg.FieldSelector != nil || opts.Cache.DefaultLabelSelector != nil || opts.Cache.DefaultFieldSelector != nil || len(opts.Cache.ByObject) != 0 {
			t.Fatalf("wrong namespace or filtered cache: %+v", opts.Cache)
		}
		if opts.Metrics.BindAddress != "0" || opts.Metrics.FilterProvider != nil || opts.LeaderElection || opts.LeaderElectionID != "" {
			t.Fatal("metrics or leader election enabled")
		}
		if opts.HealthProbeBindAddress != ":8081" || opts.WebhookServer != nil || opts.Controller.SkipNameValidation != nil {
			t.Fatal("unexpected probe, webhook, or production name-validation options")
		}
	}
}

// A namespace error must win over an unusable kubeconfig. No client or
// manager is needed to reject syntax, and valid syntax proves only syntax.
func TestUnitInvalidStartup(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing-kubeconfig"))
	t.Setenv("WATCH_NAMESPACE", "environment-fallback")
	for _, args := range [][]string{nil, {"--watch-namespace="}, {"--watch-namespace=A"}, {"--watch-namespace=a,b"}} {
		err := run(context.Background(), args)
		if err == nil || !strings.Contains(err.Error(), "watch-namespace") {
			t.Fatalf("expected namespace configuration error before kubeconfig access, got %v", err)
		}
	}
	ns, err := parseWatchNamespace([]string{"--watch-namespace=not-known-to-exist"})
	if err != nil || ns != "not-known-to-exist" {
		t.Fatalf("syntax validation must not access cluster: namespace %q, error %v", ns, err)
	}
}
