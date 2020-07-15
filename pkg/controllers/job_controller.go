package controllers

import (
	"context"
	"fmt"

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
	Writer  vulnerabilities.Writer
}

func (r *JobReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("job", req.NamespacedName)
	if req.Namespace != r.StarboardNamespace {
		return ctrl.Result{}, nil
	}

	j := &batchv1.Job{}
	err := r.Client.Get(context.Background(), req.NamespacedName, j)
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
		err := r.processCompleteScanJob(context.Background(), j)
		if err != nil {
			return ctrl.Result{}, err
		}
	case batchv1.JobFailed:
		err := r.processFailedScanJob(context.Background(), j)
		if err != nil {
			return ctrl.Result{}, err
		}
	default:
		r.Log.Info("Unrecognized scan job condition: %v", "condition", jobCondition)
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *JobReconciler) processCompleteScanJob(ctx context.Context, scanJob *batchv1.Job) error {
	r.Log.Info("Started processing complete scan job")
	workload, err := kube.ObjectFromLabelsSet(scanJob.Labels)
	if err != nil {
		return fmt.Errorf("getting workload from scan job labels set: %w", err)
	}

	r.Log.Info("Getting vulnerability reports by scan job")
	vulnerabilityReports, err := r.Scanner.GetVulnerabilityReportsByScanJob(ctx, scanJob)
	if err != nil {
		return err
	}

	r.Log.Info("Writing vulnerability reports", "workload", workload)
	err = r.Writer.Write(ctx, workload, vulnerabilityReports)
	if err != nil {
		return fmt.Errorf("writing vulnerability reports: %v", err)
	}
	r.Log.Info("Finished processing complete scan job")
	r.Log.Info("Deleting complete scan job")
	return r.Client.Delete(ctx, scanJob)
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
