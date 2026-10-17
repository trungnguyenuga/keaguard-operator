/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	// Enable standard Kubernetes client authentication plugins.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"
	"github.com/trungnguyenuga/keaguard-operator/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(infrastructurev1alpha1.AddToScheme(scheme))
}

// parseWatchNamespace validates syntax only; installation prepares the namespace.
func parseWatchNamespace(args []string) (string, error) {
	flags := flag.NewFlagSet("keaguard", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var namespace string
	flags.StringVar(&namespace, "watch-namespace", "", "Single namespace to watch (required)")
	if err := flags.Parse(args); err != nil {
		return "", fmt.Errorf("watch-namespace configuration: %w", err)
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("watch-namespace configuration: positional arguments are not supported")
	}
	if problems := validation.ValidateNamespaceName(namespace, false); len(problems) != 0 {
		return "", fmt.Errorf("watch-namespace must be one valid Kubernetes namespace name: %s", strings.Join(problems, "; "))
	}
	return namespace, nil
}

// managerOptionsForNamespace consumes an already validated namespace.
func managerOptionsForNamespace(namespace string, scheme *runtime.Scheme) ctrl.Options {
	return ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{namespace: {}},
		},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: ":8081",
		LeaderElection:         false,
	}
}

func run(ctx context.Context, args []string) error {
	namespace, err := parseWatchNamespace(args)
	if err != nil {
		return err
	}
	config, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load Kubernetes configuration: %w", err)
	}
	mgr, err := ctrl.NewManager(config, managerOptionsForNamespace(namespace, scheme))
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	if err := (&controller.KeaClusterReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Namespace: namespace,
		Scheme:    mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("register KeaCluster controller: %w", err)
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("register manager health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("register manager readiness check: %w", err)
	}
	setupLog.Info("Starting manager", "watchNamespace", namespace)
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zap.Options{Development: true})))
	if err := run(ctrl.SetupSignalHandler(), os.Args[1:]); err != nil {
		setupLog.Error(err, "Manager stopped")
		os.Exit(1)
	}
}
