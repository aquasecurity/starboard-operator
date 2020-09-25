package controllers

import (
	"context"
	"fmt"
	"reflect"

	"github.com/aquasecurity/starboard-operator/pkg/reports"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type VulnerabilityReportReconciler struct {
	Log    logr.Logger
	Client client.Client
	Store  reports.StoreInterface
}

func (r *VulnerabilityReportReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	report := &v1alpha1.VulnerabilityReport{}

	log := r.Log.WithValues("vulnerabilityreport", req.NamespacedName)

	// Retrieve the VulnerabilityReport from cache.
	err := r.Client.Get(ctx, req.NamespacedName, report)
	if err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Ignoring VulnerabilityReport that must have been deleted")
		return ctrl.Result{}, nil
	} else if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting vulnerabilityreport from cache: %w", err)
	}

	// Check if the VulnerabilityReport is being deleted.
	if report.DeletionTimestamp != nil {
		log.V(1).Info("Ignoring VulnerabilityReport that is being deleted")
		return ctrl.Result{}, nil
	}

	containerName, ok := report.Labels[kube.LabelContainerName]
	if !ok {
		log.Error(nil, fmt.Sprintf("VulnerabilityReport without %s label", kube.LabelContainerName))
		return ctrl.Result{}, nil
	}

	// Get the owner of the VulnerabilityReport. Initially it's set to the immediate
	// owner of a supervised Pod.
	reportOwner, reportOwnerGVK, err := r.Store.GetOwnerOf(ctx, report)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting report owner: %w", err)
	}

	if reportOwner == nil {
		log.V(1).Info("Ignoring VulnerabilityReport without owner set")
		return ctrl.Result{}, nil
	}

	if reportOwnerGVK.Kind != string(kube.KindReplicaSet) {
		log.V(1).Info("Ignoring VulnerabilityReport not owned by ReplicaSet", "owner", reportOwnerGVK)
		return ctrl.Result{}, nil
	}

	// Get the controller of the VulnerabilityReport's owner.
	ownerController, ownerControllerGVK, err := r.Store.GetControllerOf(ctx, *reportOwner)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("getting owner controller: %w", err)
	}

	if ownerController == nil {
		log.Info("Ignoring VulnerabilityReport without parent owner set")
		return ctrl.Result{}, nil
	}

	if ownerControllerGVK.Kind != string(kube.KindDeployment) {
		log.V(1).Info("Ignoring VulnerabilityReport owner controller not equal to Deployment")
		return ctrl.Result{}, nil
	}

	deploymentRevision := (*ownerController).GetAnnotations()["deployment.kubernetes.io/revision"]
	replicaSetRevision := (*reportOwner).GetAnnotations()["deployment.kubernetes.io/revision"]
	if deploymentRevision != "" && deploymentRevision != replicaSetRevision {
		log.V(1).Info("Ignoring VulnerabilityReport owned by ReplicaSet from previous revision",
			"deployment revision", deploymentRevision,
			"replicaset revision", replicaSetRevision)
		return ctrl.Result{}, nil
	}

	obj := kube.Object{
		Kind:      kube.Kind(ownerControllerGVK.Kind),
		Name:      (*ownerController).GetName(),
		Namespace: (*ownerController).GetNamespace(),
	}

	vulnerabilityReports, err := r.Store.Read(ctx, obj)
	if err != nil {
		return ctrl.Result{}, err
	}

	if existingReport, ok := vulnerabilityReports[containerName]; ok && reflect.DeepEqual(existingReport, report.Report) {
		log.Info("VulnerabilityReport already exists and is up to date", "owner", obj)
		return ctrl.Result{}, nil
	}

	log.Info("Creating copy of VulnerabilityReport", "owner", obj)
	var reportCopy v1alpha1.VulnerabilityReport
	report.DeepCopyInto(&reportCopy)

	err = r.Store.WriteAll(ctx, obj, vulnerabilities.WorkloadVulnerabilities{
		containerName: reportCopy.Report,
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("writiing VulnerabilityReport: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *VulnerabilityReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.VulnerabilityReport{}).
		Complete(r)
}
