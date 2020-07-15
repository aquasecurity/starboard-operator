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
	Namespace string
	client.Client
	Scanner vulnerabilities.ScannerAsync
	Log     logr.Logger
	Scheme  *runtime.Scheme
}

func (r *PodReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("pod", req.NamespacedName)

	if r.Namespace != "" && r.Namespace != req.Namespace {
		return ctrl.Result{}, nil
	}

	p := &corev1.Pod{}

	err := r.Client.Get(context.Background(), req.NamespacedName, p)
	if err != nil && errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// Check if the Pod has been scheduled to a Node and all its containers are ready
	if !r.hasContainersReadyCondition(p) {
		return ctrl.Result{}, nil
	}

	owner := r.getImmediateOwnerReference(p)

	// Check if the Pod's containers have corresponding vulnerability reports
	hasDesiredState, err := r.hasVulnerabilityReports(owner, p)
	if err != nil {
		return ctrl.Result{}, err
	}

	if hasDesiredState {
		return ctrl.Result{}, nil
	}

	// Create a scan Job to find vulnerabilities in the Pod container images
	err = r.ensureScanJob(owner, p)
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

// Check if we have scan reports for the specified pod
func (r *PodReconciler) hasVulnerabilityReports(owner kube.Object, p *corev1.Pod) (bool, error) {
	vulnerabilityList := &starboard.VulnerabilityList{}
	err := r.Client.List(context.Background(), vulnerabilityList, client.MatchingLabels{
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

func (r *PodReconciler) ensureScanJob(owner kube.Object, p *corev1.Pod) error {
	jobList := &batchv1.JobList{}
	err := r.Client.List(context.Background(), jobList, client.MatchingLabels{
		kube.LabelResourceNamespace: p.Namespace,
		kube.LabelResourceKind:      string(owner.Kind),
		kube.LabelResourceName:      owner.Name,
	}, client.InNamespace("starboard"))
	if err != nil {
		return err
	}

	if len(jobList.Items) > 0 {
		return nil
	}

	scanJob, err := r.Scanner.PrepareScanJob(context.Background(), owner, p.Spec)
	if err != nil {
		return err
	}

	r.Log.Info("Creating scan job", "workload.name", owner.Name, "workload.namespace", owner.Namespace, "pod.name", p.Name)
	return r.Client.Create(context.Background(), scanJob, &client.CreateOptions{})
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
