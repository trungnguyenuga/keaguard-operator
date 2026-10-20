package e2e

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestUnitM2CleanupHoldReleaseRetriesResourceVersionConflict(t *testing.T) {
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Namespace: m2LabProfile.runtimeNamespace,
		Name:      "cleanup-conflict",
		UID:       "set-uid",
		Finalizers: []string{
			"foreign.example/retain",
			t14HoldFinalizer,
		},
	}}
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	previousAdmin := admin
	updates := 0
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(set).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, object client.Object, opts ...client.UpdateOption) error {
			updates++
			if updates == 1 {
				current := &appsv1.StatefulSet{}
				key := client.ObjectKeyFromObject(object)
				if err := c.Get(ctx, key, current); err != nil {
					return err
				}
				current.Labels = map[string]string{"controller.example/revision": "fresh"}
				if err := c.Update(ctx, current); err != nil {
					return err
				}
				return apierrors.NewConflict(schema.GroupResource{Resource: "statefulsets"}, object.GetName(), errors.New("simulated controller resourceVersion update"))
			}
			return c.Update(ctx, object, opts...)
		},
	}).Build()
	defer func() { admin = previousAdmin }()

	identity := m2FixtureIdentity{Key: client.ObjectKeyFromObject(set), GVK: appsv1.SchemeGroupVersion.WithKind("StatefulSet"), UID: set.UID}
	if err := m2ReleaseCleanupHold(context.Background(), identity); err != nil {
		t.Fatalf("release did not retry against the fresh StatefulSet version: %v", err)
	}
	if updates != 2 {
		t.Fatalf("expected one conflict and one retry, observed %d updates", updates)
	}
	actual := &appsv1.StatefulSet{}
	if err := admin.Get(context.Background(), identity.Key, actual); err != nil {
		t.Fatal(err)
	}
	if actual.UID != identity.UID || actual.Labels["controller.example/revision"] != "fresh" || len(actual.Finalizers) != 1 || actual.Finalizers[0] != "foreign.example/retain" {
		t.Fatalf("retry did not preserve current object state and only remove the exact test hold: %+v", actual.ObjectMeta)
	}
}

func TestUnitM2CleanupHoldReleaseRefusesReplacementUIDAfterConflict(t *testing.T) {
	set := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
		Namespace:  m2LabProfile.runtimeNamespace,
		Name:       "cleanup-replaced",
		UID:        "old-set-uid",
		Finalizers: []string{t14HoldFinalizer},
	}}
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	previousAdmin := admin
	updates := 0
	admin = fake.NewClientBuilder().WithScheme(scheme).WithObjects(set).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, object client.Object, opts ...client.UpdateOption) error {
			updates++
			old := &appsv1.StatefulSet{}
			key := client.ObjectKeyFromObject(object)
			if err := c.Get(ctx, key, old); err != nil {
				return err
			}
			old.Finalizers = nil
			if err := c.Update(ctx, old); err != nil {
				return err
			}
			if err := c.Delete(ctx, old); err != nil {
				return err
			}
			replacement := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{
				Namespace:  object.GetNamespace(),
				Name:       object.GetName(),
				UID:        "foreign-set-uid",
				Finalizers: []string{"foreign.example/retain"},
			}}
			if err := c.Create(ctx, replacement); err != nil {
				return err
			}
			return apierrors.NewConflict(schema.GroupResource{Resource: "statefulsets"}, object.GetName(), errors.New("simulated replacement during release"))
		},
	}).Build()
	defer func() { admin = previousAdmin }()

	identity := m2FixtureIdentity{Key: client.ObjectKeyFromObject(set), GVK: appsv1.SchemeGroupVersion.WithKind("StatefulSet"), UID: set.UID}
	if err := m2ReleaseCleanupHold(context.Background(), identity); err == nil {
		t.Fatal("replacement incarnation was accepted while releasing the old cleanup hold")
	}
	if updates != 1 {
		t.Fatalf("foreign replacement must not be updated, observed %d update submissions", updates)
	}
	actual := &appsv1.StatefulSet{}
	if err := admin.Get(context.Background(), identity.Key, actual); err != nil {
		t.Fatal(err)
	}
	if actual.UID != "foreign-set-uid" || len(actual.Finalizers) != 1 || actual.Finalizers[0] != "foreign.example/retain" {
		t.Fatalf("foreign replacement was modified: %+v", actual.ObjectMeta)
	}
}
