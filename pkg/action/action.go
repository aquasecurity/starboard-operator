package action

import (
	"context"
	"fmt"

	"k8s.io/klog"

	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/crd"
	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"

	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	batch "k8s.io/api/batch/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/aquasecurity/starboard/pkg/kube"
	core "k8s.io/api/core/v1"
)

// Starboard action defines methods for the Starboard Security Operator.
// The interface clearly sets the border between the operator's business
// logic and various frameworks available for implementing Kubernetes
// operators such as kubebuilder and Operator SDK.
//
// With such abstraction we can potentially change the infrastructure
// code required by such frameworks without modifying the business logic.
type Starboard interface {
	IsPodScheduled(old, new *core.Pod) bool
	SubmitScanJobByPod(ctx context.Context, spec *core.Pod) error
	IsScanJobFinished(ctx context.Context, job *batch.Job) (bool, batch.JobConditionType)
	ProcessCompleteScanJob(ctx context.Context, scanJob *batch.Job) error
	ProcessFailedScanJob(ctx context.Context, scanJob *batch.Job) error
}

// NewStarboard construct a new Starboard action with the specified configuration
// and Kubernetes clientsets.
func NewStarboard(config etc.Config,
	kubeClientset kubernetes.Interface,
	starboardClientset starboard.Interface,
	pods *pod.Manager,
	scanner vulnerabilities.ScannerAsync) Starboard {
	return &action{
		config:        config,
		kubeClientset: kubeClientset,
		pods:          pods,
		writer:        crd.NewWriter(starboardClientset),
		scanner:       scanner,
	}
}

type action struct {
	config        etc.Config
	kubeClientset kubernetes.Interface
	pods          *pod.Manager
	writer        vulnerabilities.Writer
	scanner       vulnerabilities.ScannerAsync
}

func (a *action) IsPodScheduled(old, new *core.Pod) bool {
	if new.Namespace == a.config.Operator.StarboardNamespace {
		return false
	}
	return !a.hasContainersReadyCondition(old) && a.hasContainersReadyCondition(new)
}

func (a *action) hasContainersReadyCondition(pod *core.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == core.ContainersReady {
			return true
		}
	}
	return false
}

func (a *action) IsScanJobFinished(_ context.Context, job *batch.Job) (bool, batch.JobConditionType) {
	// TODO Detect scan Jobs scheduled by Scanner CLI
	if job.Namespace != a.config.Operator.StarboardNamespace {
		return false, ""
	}

	if len(job.Status.Conditions) == 0 {
		return false, ""
	}

	return true, job.Status.Conditions[0].Type
}

func (a *action) SubmitScanJobByPod(ctx context.Context, pod *core.Pod) error {
	klog.Infof("Started processing pod %s/%s scheduled to node %s", pod.Namespace, pod.Name, pod.Spec.NodeName)
	workload := a.GetImmediateOwnerReference(pod)
	job, err := a.scanner.PrepareScanJob(ctx, workload, pod.Spec)
	if err != nil {
		return fmt.Errorf("preparing scan job: %w", err)
	}
	klog.Infof("Creating scan job %s/%s for workload %+v", job.Namespace, job.Name, workload)
	_, err = a.kubeClientset.BatchV1().Jobs(a.config.Operator.StarboardNamespace).Create(ctx, job, meta.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating scan job: %w", err)
	}
	klog.Infof("Finished processing pod %s/%s", pod.Namespace, pod.Name)
	return nil
}

func (a *action) ProcessCompleteScanJob(ctx context.Context, scanJob *batch.Job) error {
	klog.Infof("Started processing complete scan job: %s/%s", scanJob.Namespace, scanJob.Name)
	workload, err := kube.ObjectFromLabelsSet(scanJob.Labels)
	if err != nil {
		return fmt.Errorf("getting workload from scan job labels set: %w", err)
	}

	klog.Infof("Getting vulnerability reports by scan Job %s/%s", scanJob.Namespace, scanJob.Name)
	vulnerabilityReports, err := a.scanner.GetVulnerabilityReportsByScanJob(ctx, scanJob)
	if err != nil {
		return err
	}

	klog.Infof("Writing vulnerability reports for %+v", workload)
	err = a.writer.Write(ctx, workload, vulnerabilityReports)
	if err != nil {
		return fmt.Errorf("writing vulnerability reports: %v", err)
	}
	klog.Infof("Finished processing complete scan job: %s/%s", scanJob.Namespace, scanJob.Name)
	return nil
}

func (a *action) ProcessFailedScanJob(ctx context.Context, scanJob *batch.Job) error {
	klog.Infof("Processing failed scan job: %s/%s", scanJob.Namespace, scanJob.Name)
	statuses, err := a.pods.GetTerminatedContainersStatusesByJob(ctx, scanJob)
	if err != nil {
		return fmt.Errorf("getting terminated containers statuses: %w", err)
	}
	for container, status := range statuses {
		if status.ExitCode == 0 {
			continue
		}
		klog.Errorf("Scan job container %s %s: %s", container, status.Reason, status.Message)
	}
	return nil
}

// TODO Climb up the owners hierarchy and use the root?
// TODO Move such utility function to libstarboard
// TODO Add GetRootOwnerReference to have another option
func (a *action) GetImmediateOwnerReference(pod *core.Pod) kube.Object {
	ownerRef := meta.GetControllerOf(pod)
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
