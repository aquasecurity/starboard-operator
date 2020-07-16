package controllers

import (
	"context"
	"reflect"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	batchv1 "k8s.io/api/batch/v1"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PodReconciler struct {
	StarboardNamespace string
	Namespace          string
	client.Client
	Scanner vulnerabilities.ScannerAsync
	Log     logr.Logger
	Scheme  *runtime.Scheme
}

// Reconcile resolves the actual state of the system against the desired state of the system.
// The desired state is that there is a vulnerability report associated with the controller
// managing the given Pod.
// Since the scanning is asynchronous, the desired state is also when there's a pending scan
// Job for the underlying workload.
//
// As Kubernetes invokes the Reconcile() function multiple times throughout the lifecycle
// of a Pod, it is important that the implementation be idempotent to prevent the
// creation of duplicate scan Jobs or vulnerability reports.
//
// The Reconcile function returns two object which indicate whether or not Kubernetes
// should requeue the request.
func (r *PodReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	if r.Namespace != "" && r.Namespace != req.Namespace {
		return ctrl.Result{}, nil
	}

	pod := &corev1.Pod{}

	err := r.Client.Get(ctx, req.NamespacedName, pod)
	if err != nil && errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// Check if the Pod is being terminated
	if pod.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	// Check if the Pod has been scheduled to a Node and all its containers are ready
	if !r.hasContainersReadyCondition(pod) {
		return ctrl.Result{}, nil
	}

	owner := r.getImmediateOwnerReference(pod)

	// Check if the Pod's containers have corresponding vulnerability reports
	hasDesiredState, err := r.hasVulnerabilityReports(ctx, owner, pod)
	if err != nil {
		return ctrl.Result{}, err
	}

	if hasDesiredState {
		return ctrl.Result{}, nil
	}

	// Create a scan Job to find vulnerabilities in the Pod container images
	err = r.ensureScanJob(ctx, owner, pod)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *PodReconciler) hasContainersReadyCondition(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.ContainersReady {
			return true
		}
	}
	return false
}

// hasVulnerabilityReports checks if the vulnerability reports exist for the specified workload.
func (r *PodReconciler) hasVulnerabilityReports(ctx context.Context, owner kube.Object, p *corev1.Pod) (bool, error) {
	vulnerabilityList := &starboard.VulnerabilityList{}
	err := r.Client.List(ctx, vulnerabilityList, client.MatchingLabels{
		kube.LabelResourceNamespace: p.Namespace,
		kube.LabelResourceKind:      string(owner.Kind),
		kube.LabelResourceName:      owner.Name,
	}, client.InNamespace(p.Namespace))
	if err != nil {
		return false, err
	}

	actual := map[string]bool{}
	for _, items := range vulnerabilityList.Items {
		if containerName, ok := items.Labels[kube.LabelContainerName]; ok {
			actual[containerName] = true
		}
	}

	expected := map[string]bool{}
	for _, container := range p.Spec.Containers {
		expected[container.Name] = true
	}

	return reflect.DeepEqual(actual, expected), nil
}

func (r *PodReconciler) ensureScanJob(ctx context.Context, owner kube.Object, p *corev1.Pod) error {
	log := r.Log.WithValues("owner.kind", owner.Kind,
		"owner.name", owner.Name,
		"owner.namespace", owner.Namespace,
		"pod.name", p.Name)

	jobList := &batchv1.JobList{}
	err := r.Client.List(ctx, jobList, client.MatchingLabels{
		kube.LabelResourceNamespace: p.Namespace,
		kube.LabelResourceKind:      string(owner.Kind),
		kube.LabelResourceName:      owner.Name,
	}, client.InNamespace(r.StarboardNamespace))
	if err != nil {
		return err
	}

	if len(jobList.Items) > 0 {
		log.Info("Scan job already exists")
		return nil
	}

	scanJob, err := r.Scanner.PrepareScanJob(ctx, owner, p.Spec)
	if err != nil {
		return err
	}

	log.Info("Creating scan job", "job.name", scanJob.Name, "job.namespace", scanJob.Namespace)
	return r.Client.Create(ctx, scanJob, &client.CreateOptions{})
}

func (r *PodReconciler) getImmediateOwnerReference(pod *corev1.Pod) kube.Object {
	ownerRef := metav1.GetControllerOf(pod)
	if ownerRef != nil {
		return kube.Object{
			Namespace: pod.Namespace,
			Kind:      kube.Kind(ownerRef.Kind),
			Name:      ownerRef.Name,
		}
	}
	return kube.Object{
		Namespace: pod.Namespace,
		Kind:      kube.KindPod,
		Name:      pod.Name,
	}
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
