package controllers

import (
	"context"
	"fmt"
	"github.com/aquasecurity/starboard-operator/pkg/resources"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/starboard-operator/pkg/etc"
	"github.com/aquasecurity/starboard-operator/pkg/logs"
	"github.com/aquasecurity/starboard-operator/pkg/scanner"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	pods "github.com/aquasecurity/starboard/pkg/kube/pod"
	corev1 "k8s.io/api/core/v1"

	"github.com/aquasecurity/starboard-operator/pkg/reports"
	"github.com/aquasecurity/starboard/pkg/kube"
	"k8s.io/apimachinery/pkg/api/errors"

	batchv1 "k8s.io/api/batch/v1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type JobReconciler struct {
	Config     etc.Operator
	Client     client.Client
	LogsReader *logs.Reader
	Log        logr.Logger
	Scheme     *runtime.Scheme
	Scanner    scanner.VulnerabilityScanner
	Store      reports.StoreInterface
}

func (r *JobReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("job", req.NamespacedName)

	if req.Namespace != r.Config.Namespace {
		log.V(1).Info("Ignoring Job not managed by this operator")
		return ctrl.Result{}, nil
	}

	job := &batchv1.Job{}
	err := r.Client.Get(ctx, req.NamespacedName, job)
	if err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Ignoring Job that must have been deleted")
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting job from cache: %w", err)
	}

	if len(job.Status.Conditions) == 0 {
		log.V(1).Info("Ignoring Job without status conditions")
		return ctrl.Result{}, nil
	}

	switch jobCondition := job.Status.Conditions[0].Type; jobCondition {
	case batchv1.JobComplete:
		err := r.processCompleteScanJob(ctx, job)
		if err != nil {
			return ctrl.Result{}, err
		}
	case batchv1.JobFailed:
		err := r.processFailedScanJob(ctx, job)
		if err != nil {
			return ctrl.Result{}, err
		}
	default:
		log.Info("Unrecognized scan job condition", "condition", jobCondition)
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *JobReconciler) processCompleteScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	log := r.Log.WithValues("job", fmt.Sprintf("%s/%s", scanJob.Namespace, scanJob.Name))
	workload, err := kube.ObjectFromLabelsSet(scanJob.Labels)
	if err != nil {
		return fmt.Errorf("getting workload from scan job labels set: %w", err)
	}

	containerImages, err := resources.GetContainerImagesFromJob(scanJob)
	if err != nil {
		return fmt.Errorf("getting container images: %w", err)
	}

	hasVulnerabilityReports, err := r.Store.HasVulnerabilityReports(ctx, workload, containerImages)
	if err != nil {
		return err
	}

	if hasVulnerabilityReports {
		log.V(1).Info("VulnerabilityReports already exist", "owner", workload)
		log.V(1).Info("Deleting scan job")
		return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
	}

	pod, err := r.GetPodControlledBy(ctx, scanJob)
	if err != nil {
		return fmt.Errorf("getting pod controlled by %s/%s: %w", scanJob.Namespace, scanJob.Name, err)
	}

	vulnerabilityReports := make(map[string]v1alpha1.VulnerabilityScanResult)
	for _, container := range pod.Spec.Containers {
		logsReader, err := r.LogsReader.GetLogsForPod(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &corev1.PodLogOptions{
			Container: container.Name,
			Follow:    true,
		})
		if err != nil {
			return fmt.Errorf("getting logs for pod %s/%s: %w", pod.Namespace, pod.Name, err)
		}
		vulnerabilityReports[container.Name], err = r.Scanner.ParseVulnerabilityReport(containerImages[container.Name], logsReader)
		if err != nil {
			return err
		}
		_ = logsReader.Close()
	}

	log.Info("Writing VulnerabilityReports", "owner", workload)
	err = r.Store.Write(ctx, workload, vulnerabilityReports)
	if err != nil {
		return fmt.Errorf("writing vulnerability reports: %w", err)
	}
	log.V(1).Info("Deleting complete scan job")
	return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
}

func (r *JobReconciler) GetPodControlledBy(ctx context.Context, job *batchv1.Job) (*corev1.Pod, error) {
	controllerUID, ok := job.Spec.Selector.MatchLabels["controller-uid"]
	if !ok {
		return nil, fmt.Errorf("controller-uid not found for job %s/%s", job.Namespace, job.Name)
	}
	podList := &corev1.PodList{}
	err := r.Client.List(ctx, podList, client.MatchingLabels{"controller-uid": controllerUID})
	if err != nil {
		return nil, fmt.Errorf("listing pods controlled by job %s/%s: %w", job.Namespace, job.Name, err)
	}
	if len(podList.Items) != 1 {
		return nil, fmt.Errorf("expected 1 Pod, but got %d", len(podList.Items))
	}
	return podList.Items[0].DeepCopy(), nil
}

func (r *JobReconciler) processFailedScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	pod, err := r.GetPodControlledBy(ctx, scanJob)
	if err != nil {
		return err
	}
	statuses := pods.GetTerminatedContainersStatusesByPod(pod)
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		r.Log.Error(nil, "Scan job container", "container", container, "status.reason", status.Reason, "status.message", status.Message)
	}
	r.Log.V(1).Info("Deleting failed scan job")
	return r.Client.Delete(ctx, scanJob, client.PropagationPolicy(metav1.DeletePropagationBackground))
}

func (r *JobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}).
		Complete(r)
}
