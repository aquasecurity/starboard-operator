package controllers

import (
	"context"
	"fmt"
	"reflect"

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
	if req.Namespace != r.Config.StarboardNamespace {
		return ctrl.Result{}, nil
	}

	j := &batchv1.Job{}
	err := r.Client.Get(ctx, req.NamespacedName, j)
	if err != nil && errors.IsNotFound(err) {
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, err
	}

	if len(j.Status.Conditions) == 0 {
		return ctrl.Result{}, nil
	}

	switch jobCondition := j.Status.Conditions[0].Type; jobCondition {
	case batchv1.JobComplete:
		err := r.processCompleteScanJob(ctx, j)
		if err != nil {
			return ctrl.Result{}, err
		}
	case batchv1.JobFailed:
		err := r.processFailedScanJob(ctx, j)
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
	log := r.Log.WithValues("job.name", scanJob.Name, "job.namespace", scanJob.Namespace)
	log.Info("Started processing complete scan job")
	workload, err := kube.ObjectFromLabelsSet(scanJob.Labels)
	if err != nil {
		return fmt.Errorf("getting workload from scan job labels set: %w", err)
	}

	containerImages, err := r.getContainerImagesFrom(scanJob)
	if err != nil {
		return err
	}

	hasVulnerabilityReports, err := r.hasVulnerabilityReports(ctx, workload, containerImages)
	if err != nil {
		return err
	}

	if hasVulnerabilityReports {
		log.Info("Vulnerability reports already exist")
		return r.Client.Delete(ctx, scanJob)
	}

	pod, err := r.GetPodControlledBy(ctx, scanJob)
	if err != nil {
		return fmt.Errorf("getting pod controlled by %s/%s: %w", scanJob.Namespace, scanJob.Name, err)
	}

	vulnerabilityReports := make(map[string]v1alpha1.VulnerabilityReport)
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

	log.Info("Writing vulnerability reports", "workload", workload)
	err = r.Store.Write(ctx, workload, vulnerabilityReports)
	if err != nil {
		return fmt.Errorf("writing vulnerability reports: %w", err)
	}
	log.Info("Finished processing complete scan job")
	log.Info("Deleting complete scan job")
	return r.Client.Delete(ctx, scanJob)
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

func (r *JobReconciler) hasVulnerabilityReports(ctx context.Context, owner kube.Object, containerImages kube.ContainerImages) (bool, error) {
	vulnerabilityReports, err := r.Store.Read(ctx, owner)
	if err != nil {
		return false, err
	}

	actual := map[string]bool{}
	for containerName, _ := range vulnerabilityReports {
		actual[containerName] = true
	}

	expected := map[string]bool{}
	for containerName, _ := range containerImages {
		expected[containerName] = true
	}

	return reflect.DeepEqual(actual, expected), nil
}

// TODO We have similar code in other places
func (r *JobReconciler) getContainerImagesFrom(job *batchv1.Job) (kube.ContainerImages, error) {
	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = job.Annotations[kube.AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("scan job does not have required annotation: %s", kube.AnnotationContainerImages)
	}
	containerImages := kube.ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("reading scan job annotation: %s: %w", kube.AnnotationContainerImages, err)
	}
	return containerImages, nil
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
	r.Log.Info("Deleting failed scan job")
	return r.Client.Delete(ctx, scanJob)
}

func (r *JobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&batchv1.Job{}).
		Complete(r)
}
