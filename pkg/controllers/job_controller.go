package controllers

import (
	"context"
	"fmt"
	"reflect"

	"github.com/aquasecurity/starboard-security-operator/pkg/reports"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube"
	pods "github.com/aquasecurity/starboard/pkg/kube/pod"
	"k8s.io/apimachinery/pkg/api/errors"

	batchv1 "k8s.io/api/batch/v1"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type JobReconciler struct {
	StarboardNamespace string
	client.Client
	Log     logr.Logger
	Scheme  *runtime.Scheme
	Pods    *pods.Manager
	Scanner vulnerabilities.ScannerAsync
	Store   reports.StoreInterface
}

func (r *JobReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("job", req.NamespacedName)
	if req.Namespace != r.StarboardNamespace {
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

	hasVulnerabilityReports, err := r.hasVulnerabilityReports(ctx, workload, scanJob)
	if err != nil {
		return err
	}
	if hasVulnerabilityReports {
		return r.Client.Delete(ctx, scanJob)
	}

	log.Info("Getting vulnerability reports by scan job")
	vulnerabilityReports, err := r.Scanner.GetVulnerabilityReportsByScanJob(ctx, scanJob)
	if err != nil {
		return err
	}

	log.Info("Writing vulnerability reports", "workload", workload)
	err = r.Store.Write(ctx, workload, vulnerabilityReports)
	if err != nil {
		return fmt.Errorf("writing vulnerability reports: %v", err)
	}
	log.Info("Finished processing complete scan job")
	log.Info("Deleting complete scan job")
	return r.Client.Delete(ctx, scanJob)
}

// Check if we have scan reports for the specified pod
func (r *JobReconciler) hasVulnerabilityReports(ctx context.Context, owner kube.Object, job *batchv1.Job) (bool, error) {
	vulnerabilityReports, err := r.Store.Read(ctx, owner)
	if err != nil {
		return false, err
	}

	containerImages, err := r.getContainerImagesFrom(job)
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
	statuses, err := r.Pods.GetTerminatedContainersStatusesByJob(ctx, scanJob)
	if err != nil {
		return fmt.Errorf("getting terminated containers statuses: %w", err)
	}
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
