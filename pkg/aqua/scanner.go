package aqua

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/scanners"

	"github.com/google/uuid"

	"github.com/aquasecurity/starboard-operator/pkg/scanner"

	"github.com/aquasecurity/starboard-operator/pkg/etc"
	"github.com/aquasecurity/starboard/pkg/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
)

const (
	secretName = "starboard-operator"
)

type aquaScanner struct {
	version etc.VersionInfo
	config  etc.ScannerAquaCSP
}

func NewScanner(version etc.VersionInfo, config etc.ScannerAquaCSP) scanner.VulnerabilityScanner {
	return &aquaScanner{
		version: version,
		config:  config,
	}
}

func (s *aquaScanner) NewScanJob(resource kube.Object, spec corev1.PodSpec, options scanner.Options) (*batchv1.Job, error) {
	jobName := uuid.New().String()
	initContainerName := jobName

	containerImages := kube.ContainerImages{}
	scanJobContainers := make([]corev1.Container, len(spec.Containers))
	for i, container := range spec.Containers {
		containerImages[container.Name] = container.Image
		scanJobContainers[i] = s.newScanJobContainer(container)
	}

	containerImagesAsJSON, err := containerImages.AsJSON()
	if err != nil {
		return nil, err
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: options.Namespace,
			Labels: labels.Set{
				kube.LabelResourceKind:         string(resource.Kind),
				kube.LabelResourceName:         resource.Name,
				kube.LabelResourceNamespace:    resource.Namespace,
				"app.kubernetes.io/managed-by": "starboard-operator",
			},
			Annotations: map[string]string{
				kube.AnnotationContainerImages: containerImagesAsJSON,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          pointer.Int32Ptr(0),
			Completions:           pointer.Int32Ptr(1),
			ActiveDeadlineSeconds: scanners.GetActiveDeadlineSeconds(options.ScanJobTimeout),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels.Set{
						kube.LabelResourceKind:         string(resource.Kind),
						kube.LabelResourceName:         resource.Name,
						kube.LabelResourceNamespace:    resource.Namespace,
						"app.kubernetes.io/managed-by": "starboard-operator",
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           options.ServiceAccountName,
					AutomountServiceAccountToken: pointer.BoolPtr(false),
					NodeName:                     spec.NodeName,
					Volumes: []corev1.Volume{
						{
							Name: "scannercli",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "dockersock",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:  initContainerName,
							Image: fmt.Sprintf("aquasec/scanner:%s", s.config.Version),
							Command: []string{
								"cp",
								"/opt/aquasec/scannercli",
								"/downloads/scannercli",
							},
							VolumeMounts: []corev1.VolumeMount{
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

func (s *aquaScanner) newScanJobContainer(podContainer corev1.Container) corev1.Container {
	return corev1.Container{
		Name:            podContainer.Name,
		Image:           fmt.Sprintf("aquasec/starboard-scanner-aqua:%s", s.version.Version),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command: []string{
			"/bin/sh",
			"-c",
			fmt.Sprintf("/usr/local/bin/scanner --host $(OPERATOR_SCANNER_AQUA_CSP_HOST) --user $(OPERATOR_SCANNER_AQUA_CSP_USERNAME) --password $(OPERATOR_SCANNER_AQUA_CSP_PASSWORD) %s 2> %s",
				podContainer.Image,
				corev1.TerminationMessagePathDefault),
		},
		Env: []corev1.EnvVar{
			{
				Name: "OPERATOR_SCANNER_AQUA_CSP_HOST",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_HOST",
					},
				},
			},
			{
				Name: "OPERATOR_SCANNER_AQUA_CSP_USERNAME",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_USERNAME",
					},
				},
			},
			{
				Name: "OPERATOR_SCANNER_AQUA_CSP_PASSWORD",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: secretName,
						},
						Key: "OPERATOR_SCANNER_AQUA_CSP_PASSWORD",
					},
				},
			},
		},
		VolumeMounts: []corev1.VolumeMount{
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

func (s *aquaScanner) ParseVulnerabilityReport(_ string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error) {
	var report v1alpha1.VulnerabilityScanResult
	err := json.NewDecoder(logsReader).Decode(&report)
	return report, err
}
