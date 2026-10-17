package controller

import (
	"context"
	"errors"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sync"
	"sync/atomic"
	"time"

	infrastructurev1alpha1 "github.com/trungnguyenuga/keaguard-operator/api/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func newTestReconciler(base client.Client, reader client.Reader, namespace string) *KeaClusterReconciler {
	return &KeaClusterReconciler{Client: base, APIReader: reader, Scheme: base.Scheme(), Namespace: namespace, healthyRequeueAfter: 5 * time.Minute, blockedRequeueAfter: 30 * time.Second}
}

// Count submissions, including rejected requests, without holding locks across I/O.
type statusRecordingClient struct {
	client.Client
	mu             sync.Mutex
	patches        int
	otherStatus    int
	resourceWrites int
	patchErr       error
	beforePatch    func(context.Context, client.Object, client.Patch) error
}

func (c *statusRecordingClient) statusPatches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.patches
}
func (c *statusRecordingClient) Status() client.SubResourceWriter {
	return &statusRecordingWriter{SubResourceWriter: c.Client.Status(), recorder: c}
}

type statusRecordingWriter struct {
	client.SubResourceWriter
	recorder *statusRecordingClient
}

func (w *statusRecordingWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	c := w.recorder
	c.mu.Lock()
	c.patches++
	c.mu.Unlock()
	if c.beforePatch != nil {
		if err := c.beforePatch(ctx, obj, patch); err != nil {
			return err
		}
	}
	if c.patchErr != nil {
		return c.patchErr
	}
	return w.SubResourceWriter.Patch(ctx, obj, patch, opts...)
}

type statusReader struct {
	client.Reader
	err       error
	beforeGet func(context.Context)
}

func (r statusReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if r.beforeGet != nil {
		r.beforeGet(ctx)
	}
	if r.err != nil {
		return r.err
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func (c *statusRecordingClient) otherWrites() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.otherStatus + c.resourceWrites
}
func (c *statusRecordingClient) recordResourceWrite() { c.mu.Lock(); c.resourceWrites++; c.mu.Unlock() }
func (c *statusRecordingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.recordResourceWrite()
	return c.Client.Create(ctx, obj, opts...)
}
func (c *statusRecordingClient) Patch(ctx context.Context, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
	c.recordResourceWrite()
	return c.Client.Patch(ctx, obj, p, opts...)
}
func (c *statusRecordingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.recordResourceWrite()
	return c.Client.Update(ctx, obj, opts...)
}
func (c *statusRecordingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	c.recordResourceWrite()
	return c.Client.Delete(ctx, obj, opts...)
}
func (c *statusRecordingClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	c.recordResourceWrite()
	return c.Client.DeleteAllOf(ctx, obj, opts...)
}
func (w *statusRecordingWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	w.recorder.mu.Lock()
	w.recorder.otherStatus++
	w.recorder.mu.Unlock()
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}
func (w *statusRecordingWriter) Create(ctx context.Context, obj client.Object, sub client.Object, opts ...client.SubResourceCreateOption) error {
	w.recorder.mu.Lock()
	w.recorder.otherStatus++
	w.recorder.mu.Unlock()
	return w.SubResourceWriter.Create(ctx, obj, sub, opts...)
}

// Direct-reader counters distinguish artifact observation from mutation/status
// validation. Fault injection is restricted to fresh parent reads.
type coreRecordingReader struct {
	client.Reader
	parents, children int
	parentGet         func(*infrastructurev1alpha1.KeaCluster) error
}

func (r *coreRecordingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if p, ok := obj.(*infrastructurev1alpha1.KeaCluster); ok {
		r.parents++
		if r.parentGet != nil {
			return r.parentGet(p)
		}
	} else {
		r.children++
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

type coreRecordingClient struct {
	*statusRecordingClient
	calls, creates int
}

func (c *coreRecordingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.calls++
	return c.Client.Get(ctx, key, obj, opts...)
}
func (c *coreRecordingClient) List(ctx context.Context, obj client.ObjectList, opts ...client.ListOption) error {
	c.calls++
	return c.Client.List(ctx, obj, opts...)
}
func (c *coreRecordingClient) Status() client.SubResourceWriter {
	c.calls++
	return c.statusRecordingClient.Status()
}
func (c *coreRecordingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.calls++
	c.creates++
	return c.statusRecordingClient.Create(ctx, obj, opts...)
}

func (r *coreRecordingReader) List(ctx context.Context, obj client.ObjectList, opts ...client.ListOption) error {
	r.children++
	return r.Reader.List(ctx, obj, opts...)
}

// One-shot barriers bound both the fixture and controller waits. Callbacks run
// outside recorder locks, and all operations still forward to the real API.
type apiGate struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newAPIGate() *apiGate {
	return &apiGate{entered: make(chan struct{}), release: make(chan struct{})}
}
func (g *apiGate) wait(ctx context.Context) error {
	g.once.Do(func() { close(g.entered) })
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return fmt.Errorf("API barrier release deadline")
	}
}

type barrierClient struct {
	*statusRecordingClient
	beforeCreate func(context.Context) error
	beforePatch  func(context.Context) error
}

func (c *barrierClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.beforeCreate != nil {
		if err := c.beforeCreate(ctx); err != nil {
			return err
		}
	}
	return c.statusRecordingClient.Create(ctx, obj, opts...)
}
func (c *barrierClient) Patch(ctx context.Context, obj client.Object, p client.Patch, opts ...client.PatchOption) error {
	if c.beforePatch != nil {
		if err := c.beforePatch(ctx); err != nil {
			return err
		}
	}
	return c.statusRecordingClient.Patch(ctx, obj, p, opts...)
}

type barrierReader struct {
	client.Reader
	beforeParent func(context.Context) error
}

func (r *barrierReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*infrastructurev1alpha1.KeaCluster); ok && r.beforeParent != nil {
		if err := r.beforeParent(ctx); err != nil {
			return err
		}
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func runAPIRace(g *apiGate, operation func(context.Context) (ctrl.Result, error), fixture func()) (result ctrl.Result, err error) {
	operationCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	type outcome struct {
		result ctrl.Result
		err    error
	}
	done := make(chan outcome, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); result, err := operation(operationCtx); done <- outcome{result, err} }()
	released := false
	defer func() {
		if !released {
			close(g.release)
		}
		cancel()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-finished:
		case <-timer.C:
			result = ctrl.Result{}
			err = errors.Join(err, fmt.Errorf("API race operation did not stop after cancellation"))
		}
	}()
	select {
	case <-g.entered:
	case out := <-done:
		return out.result, fmt.Errorf("operation finished before barrier: %w", out.err)
	case <-operationCtx.Done():
		return ctrl.Result{}, fmt.Errorf("barrier entry: %w", operationCtx.Err())
	}
	fixture()
	close(g.release)
	released = true
	select {
	case out := <-done:
		return out.result, out.err
	case <-operationCtx.Done():
		return ctrl.Result{}, fmt.Errorf("operation completion: %w", operationCtx.Err())
	}
}

// A manager-local recorder counts controller submissions only; fixture clients
// bypass it. Fault controls are atomic because tests and the worker run together.
type managerFaultKey struct{}

type managerRecordingClient struct {
	*statusRecordingClient
	requests     atomic.Int64
	observations atomic.Int64
	attempts     atomic.Int64
	stage        atomic.Pointer[string]
}

func (c *managerRecordingClient) fault(stage string) bool {
	p := c.stage.Load()
	if p != nil && *p == stage {
		c.attempts.Add(1)
		return true
	}
	return false
}
func (c *managerRecordingClient) Get(ctx context.Context, k client.ObjectKey, o client.Object, opts ...client.GetOption) error {
	if _, ok := o.(*infrastructurev1alpha1.KeaCluster); ok {
		c.requests.Add(1)
		if c.fault("read") {
			return fmt.Errorf("modelled temporary parent read failure")
		}
	}
	return c.Client.Get(ctx, k, o, opts...)
}
func (c *managerRecordingClient) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	if c.fault("create") {
		c.recordResourceWrite()
		return fmt.Errorf("modelled uncertain create rejection")
	}
	return c.statusRecordingClient.Create(ctx, o, opts...)
}
func (c *managerRecordingClient) Patch(ctx context.Context, o client.Object, p client.Patch, opts ...client.PatchOption) error {
	if c.fault("patch") {
		c.recordResourceWrite()
		return fmt.Errorf("modelled uncertain patch rejection")
	}
	return c.statusRecordingClient.Patch(ctx, o, p, opts...)
}

func startTestManager(parent context.Context, namespace string, healthy, blocked time.Duration, suppressChildEvents bool) (mgr ctrl.Manager, reconciler *KeaClusterReconciler, stop func() error, err error) {
	managerCtx, cancelManager := context.WithCancel(parent)
	skip := true // Repeated controllers in this test process share the production name.
	mgr, err = ctrl.NewManager(cfg, ctrl.Options{Scheme: testScheme,
		Cache:   cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}},
		Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0", LeaderElection: false,
		Controller: config.Controller{SkipNameValidation: &skip}})
	if err != nil {
		cancelManager()
		return nil, nil, nil, err
	}
	c := &managerRecordingClient{statusRecordingClient: &statusRecordingClient{Client: mgr.GetClient()}}
	if stage, ok := parent.Value(managerFaultKey{}).(string); ok {
		c.stage.Store(&stage)
	}
	c.beforePatch = func(ctx context.Context, _ client.Object, _ client.Patch) error {
		if c.fault("status") {
			return fmt.Errorf("modelled status patch failure")
		}
		return nil
	}
	reconciler = newTestReconciler(c, &recoveryReader{Reader: mgr.GetAPIReader(), read: func(_ context.Context, o client.Object) error {
		if _, ok := o.(*corev1.ConfigMap); ok {
			c.observations.Add(1)
			if c.fault("child") {
				return fmt.Errorf("modelled child observation failure")
			}
		}
		return nil
	}}, namespace)
	reconciler.healthyRequeueAfter = healthy
	reconciler.blockedRequeueAfter = blocked
	if suppressChildEvents {
		// This sole alternative intentionally omits child delivery, keeping all other
		// production predicates/options/reconciliation unchanged.
		err = ctrl.NewControllerManagedBy(mgr).WithOptions(controllerOptions()).For(&infrastructurev1alpha1.KeaCluster{}, builder.WithPredicates(keaClusterPredicate())).Named("keacluster").Complete(reconciler)
	} else {
		err = reconciler.SetupWithManager(mgr)
	}
	if err != nil {
		cancelManager()
		return nil, nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- mgr.Start(managerCtx) }()
	var once sync.Once
	var stopErr error
	stop = func() error {
		once.Do(func() {
			cancelManager()
			select {
			case stopErr = <-done:
			case <-time.After(10 * time.Second):
				stopErr = fmt.Errorf("manager stop deadline")
			}
		})
		return stopErr
	}
	startupCtx, cancelStartup := context.WithTimeout(managerCtx, 20*time.Second)
	defer cancelStartup()
	if !mgr.GetCache().WaitForCacheSync(startupCtx) {
		err = errors.Join(fmt.Errorf("manager cache startup failed"), stop())
		return nil, nil, nil, err
	}
	return mgr, reconciler, stop, nil
}
