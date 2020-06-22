package action

import (
	"context"
	"fmt"

	"k8s.io/klog"

	"github.com/aquasecurity/starboard-security-operator/pkg/aqua"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/crd"
	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube/pod"
	"k8s.io/utils/pointer"

	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
	"github.com/google/uuid"
	batch "k8s.io/api/batch/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

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
	IsScanJobProcessable(old, new *batch.Job) bool
	ProcessCompleteScanJob(ctx context.Context, scanJob *batch.Job) error
}

// NewStarboard construct a new Starboard action with the specified configuration
// and Kubernetes clientsets.
func NewStarboard(config etc.Config,
	kubeClientset kubernetes.Interface,
	starboardClientset starboard.Interface) Starboard {
	return &action{
		config:        config,
		kubeClientset: kubeClientset,
		pods:          pod.NewPodManager(kubeClientset),
		writer:        crd.NewWriter(starboardClientset),
		converter:     aqua.NewConverter(config.ScannerAquaCSP),
	}
}

type action struct {
	config        etc.Config
	kubeClientset kubernetes.Interface
	pods          *pod.Manager
	writer        vulnerabilities.Writer
	converter     aqua.Converter
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

func (a *action) IsScanJobProcessable(_, new *batch.Job) bool {
	// TODO Detect scan Jobs scheduled by Scanner CLI
	if new.Namespace != a.config.Operator.StarboardNamespace {
		return false
	}

	if len(new.Status.Conditions) == 0 {
		return false
	}

	if new.Status.Conditions[0].Type == batch.JobComplete {
		return true
	}

	if new.Status.Conditions[0].Type == batch.JobFailed {
		return true
	}

	return false
}

func (a *action) ProcessCompleteScanJob(ctx context.Context, scanJob *batch.Job) error {
	workload, err := kube.ObjectFromLabelsSet(scanJob.Labels)
	if err != nil {
		return fmt.Errorf("getting workload from scan job labels set: %w", err)
	}

	vulnerabilityReports := make(map[string]v1alpha1.VulnerabilityReport)

	for _, container := range scanJob.Spec.Template.Spec.Containers {
		vulnerabilityReport, err := a.processVulnerabilityReportByContainer(ctx, scanJob, container.Name)
		if err != nil {
			klog.Errorf("Error while processing complete scan job by container: %v", err)
			continue
		}
		vulnerabilityReports[container.Name] = vulnerabilityReport
	}

	err = a.writer.Write(ctx, workload, vulnerabilityReports)
	if err != nil {
		return fmt.Errorf("writing vulnerability reports: %v", err)
	}
	return nil
}

func (a *action) processVulnerabilityReportByContainer(ctx context.Context, scanJob *batch.Job, container string) (v1alpha1.VulnerabilityReport, error) {
	logsReader, err := a.pods.GetContainerLogsByJob(ctx, scanJob, container)
	if err != nil {
		return v1alpha1.VulnerabilityReport{}, fmt.Errorf("getting logs from container %s of %s/%s: %w", container, scanJob.Namespace, scanJob.Name, err)
	}
	defer func() {
		_ = logsReader.Close()
	}()
	vulnerabilityReport, err := a.converter.Convert(logsReader)
	if err != nil {
		return v1alpha1.VulnerabilityReport{}, fmt.Errorf("converting logs to scan report: %w", err)
	}

	return vulnerabilityReport, nil
}

func (a *action) SubmitScanJobByPod(ctx context.Context, pod *core.Pod) error {
	job := a.prepareScanJob(pod)
	_, err := a.kubeClientset.BatchV1().Jobs(a.config.Operator.StarboardNamespace).Create(ctx, job, meta.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating scan job: %w", err)
	}
	return nil
}

func (a *action) prepareScanJob(pod *core.Pod) *batch.Job {
	resource := a.GetImmediateOwnerReference(pod)

	scanJobContainers := make([]core.Container, len(pod.Spec.Containers))
	for i, container := range pod.Spec.Containers {
		scanJobContainers[i] = a.newScanJobContainer(container)
	}

	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      uuid.New().String(),
			Namespace: a.config.Operator.StarboardNamespace,
			Labels: labels.Set{
				kube.LabelResourceKind:      string(resource.Kind),
				kube.LabelResourceName:      resource.Name,
				kube.LabelResourceNamespace: resource.Namespace,
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit: pointer.Int32Ptr(0),
			Template: core.PodTemplateSpec{
				Spec: core.PodSpec{
					RestartPolicy: core.RestartPolicyNever,
					Volumes: []core.Volume{
						{
							Name: "dockersock",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
					},
					Containers: scanJobContainers,
				},
			},
		},
	}
}

func (a *action) newScanJobContainer(podContainer core.Container) core.Container {
	return core.Container{
		Name: podContainer.Name,
		Image: fmt.Sprintf("%s/scanner:%s",
			a.config.ScannerAquaCSP.RegistryServer,
			a.config.ScannerAquaCSP.Version),
		ImagePullPolicy: core.PullNever,
		Command: []string{
			"/bin/sh",
			"-c",
			fmt.Sprintf("/opt/aquasec/scannercli scan --checkonly --host $(OPERATOR_SCANNER_AQUA_CSP_HOST) --user $(OPERATOR_SCANNER_AQUA_CSP_USER) --password $(OPERATOR_SCANNER_AQUA_CSP_PASSWORD) --local %s 2> %s",
				podContainer.Image,
				core.TerminationMessagePathDefault),
		},
		Env: []core.EnvVar{
			{
				Name: "OPERATOR_SCANNER_AQUA_CSP_HOST",
				ValueFrom: &core.EnvVarSource{
					SecretKeyRef: &core.SecretKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: "starboard-security-operator",
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_HOST",
					},
				},
			},
			{
				Name: "OPERATOR_SCANNER_AQUA_CSP_USER",
				ValueFrom: &core.EnvVarSource{
					SecretKeyRef: &core.SecretKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: "starboard-security-operator",
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_USER",
					},
				},
			},
			{
				Name: "OPERATOR_SCANNER_AQUA_CSP_PASSWORD",
				ValueFrom: &core.EnvVarSource{
					SecretKeyRef: &core.SecretKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: "starboard-security-operator",
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_PASSWORD",
					},
				},
			},
		},
		VolumeMounts: []core.VolumeMount{
			{
				Name:      "dockersock",
				MountPath: "/var/run/docker.sock",
			},
		},
	}
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
