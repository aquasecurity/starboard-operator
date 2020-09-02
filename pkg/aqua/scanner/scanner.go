package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/google/uuid"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog"
	"k8s.io/utils/pointer"
)

const (
	serviceAccountName = "starboard-security-operator"
	secretName         = "starboard-scanner-aqua"
)

// TODO Move to libstarboard
type LogsReader interface {
	GetContainerLogsByJob(ctx context.Context, job *batch.Job, container string) (io.ReadCloser, error)
}

// TODO Move to libstarboard
type NamesGenerator interface {
	Next() string
}

type RandomNamesGenerator struct {
}

func (g *RandomNamesGenerator) Next() string {
	return uuid.New().String()
}

type scanner struct {
	version        etc.VersionInfo
	config         etc.Config
	namesGenerator NamesGenerator
	logsReader     LogsReader
}

func NewScanner(version etc.VersionInfo, config etc.Config, namesGenerator NamesGenerator, logsReader LogsReader) vulnerabilities.ScannerAsync {
	return &scanner{
		version:        version,
		config:         config,
		namesGenerator: namesGenerator,
		logsReader:     logsReader,
	}
}

func (s *scanner) PrepareScanJob(_ context.Context, resource kube.Object, spec core.PodSpec) (*batch.Job, error) {
	containerImages := kube.ContainerImages{}
	scanJobContainers := make([]core.Container, len(spec.Containers))
	for i, container := range spec.Containers {
		containerImages[container.Name] = container.Image
		scanJobContainers[i] = s.newScanJobContainer(container)
	}

	containerImagesAsJSON, err := containerImages.AsJSON()
	if err != nil {
		return nil, err
	}

	return &batch.Job{
		ObjectMeta: meta.ObjectMeta{
			Name:      s.namesGenerator.Next(),
			Namespace: s.config.Operator.StarboardNamespace,
			Labels: labels.Set{
				kube.LabelResourceKind:      string(resource.Kind),
				kube.LabelResourceName:      resource.Name,
				kube.LabelResourceNamespace: resource.Namespace,
			},
			Annotations: map[string]string{
				kube.AnnotationContainerImages: containerImagesAsJSON,
			},
		},
		Spec: batch.JobSpec{
			BackoffLimit: pointer.Int32Ptr(0),
			Template: core.PodTemplateSpec{
				Spec: core.PodSpec{
					RestartPolicy:      core.RestartPolicyNever,
					ServiceAccountName: serviceAccountName,
					NodeName:           spec.NodeName,
					Volumes: []core.Volume{
						{
							Name: "scannercli",
							VolumeSource: core.VolumeSource{
								EmptyDir: &core.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "dockersock",
							VolumeSource: core.VolumeSource{
								HostPath: &core.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
					},
					InitContainers: []core.Container{
						{
							Name:  "download",
							Image: fmt.Sprintf("aquasec/scanner:%s", s.config.ScannerAquaCSP.Version),
							Command: []string{
								"cp",
								"/opt/aquasec/scannercli",
								"/downloads/scannercli",
							},
							VolumeMounts: []core.VolumeMount{
								{
									Name:      "scannercli",
									MountPath: "/downloads",
								},
							},
						},
					},
					Containers: scanJobContainers,
				},
			},
		},
	}, nil
}

func (s *scanner) newScanJobContainer(podContainer core.Container) core.Container {
	return core.Container{
		Name:            podContainer.Name,
		Image:           fmt.Sprintf("aquasec/starboard-scanner-aqua:%s", s.version.Version),
		ImagePullPolicy: core.PullIfNotPresent,
		Command: []string{
			"/bin/sh",
			"-c",
			fmt.Sprintf("/usr/local/bin/scanner --host $(OPERATOR_SCANNER_AQUA_CSP_HOST) --user $(OPERATOR_SCANNER_AQUA_CSP_USER) --password $(OPERATOR_SCANNER_AQUA_CSP_PASSWORD) %s 2> %s",
				podContainer.Image,
				core.TerminationMessagePathDefault),
		},
		Env: []core.EnvVar{
			{
				Name: "OPERATOR_SCANNER_AQUA_CSP_HOST",
				ValueFrom: &core.EnvVarSource{
					SecretKeyRef: &core.SecretKeySelector{
						LocalObjectReference: core.LocalObjectReference{
							Name: secretName,
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
							Name: secretName,
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
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_PASSWORD",
					},
				},
			},
		},
		VolumeMounts: []core.VolumeMount{
			{
				Name:      "scannercli",
				MountPath: "/usr/local/bin/scannercli",
				SubPath:   "scannercli",
			},
			{
				Name:      "dockersock",
				MountPath: "/var/run/docker.sock",
			},
		},
	}
}

func (s *scanner) GetVulnerabilityReportsByScanJob(ctx context.Context, scanJob *batch.Job) (vulnerabilities.WorkloadVulnerabilities, error) {
	vulnerabilityReports := make(map[string]v1alpha1.VulnerabilityReport)

	var containerImagesAsJSON string
	var ok bool

	if containerImagesAsJSON, ok = scanJob.Annotations[kube.AnnotationContainerImages]; !ok {
		return nil, fmt.Errorf("scan job does not have required annotation: %s", kube.AnnotationContainerImages)
	}
	containerImages := kube.ContainerImages{}
	err := containerImages.FromJSON(containerImagesAsJSON)
	if err != nil {
		return nil, fmt.Errorf("reading scan job annotation: %s: %w", kube.AnnotationContainerImages, err)
	}

	for _, container := range scanJob.Spec.Template.Spec.Containers {
		vulnerabilityReport, err := s.processVulnerabilityReportByContainer(ctx, scanJob, container.Name, containerImages[container.Name])
		if err != nil {
			klog.Errorf("Error while processing complete scan job by container: %v", err)
			continue
		}
		vulnerabilityReports[container.Name] = vulnerabilityReport
	}
	return vulnerabilityReports, nil
}

func (s *scanner) processVulnerabilityReportByContainer(ctx context.Context, scanJob *batch.Job, container string, imageRef string) (v1alpha1.VulnerabilityReport, error) {
	logsReader, err := s.logsReader.GetContainerLogsByJob(ctx, scanJob, container)
	if err != nil {
		return v1alpha1.VulnerabilityReport{}, fmt.Errorf("getting logs from container %s of %s/%s: %w", container, scanJob.Namespace, scanJob.Name, err)
	}
	defer func() {
		_ = logsReader.Close()
	}()
	vulnerabilityReport, err := s.convert(logsReader)
	if err != nil {
		return v1alpha1.VulnerabilityReport{}, fmt.Errorf("converting logs to scan report: %w", err)
	}

	return vulnerabilityReport, nil
}

func (s *scanner) convert(in io.Reader) (v1alpha1.VulnerabilityReport, error) {
	var report v1alpha1.VulnerabilityReport
	err := json.NewDecoder(in).Decode(&report)
	return report, err
}
