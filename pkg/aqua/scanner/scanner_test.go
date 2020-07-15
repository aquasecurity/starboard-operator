package scanner

import (
	"context"
	"io"
	"testing"

	"k8s.io/utils/pointer"

	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mockNamesGenerator struct {
	mock.Mock
}

func (m *mockNamesGenerator) Next() string {
	args := m.Called()
	return args.String(0)
}

type mockLogsReader struct {
	mock.Mock
}

func (m *mockLogsReader) GetContainerLogsByJob(ctx context.Context, job *batch.Job, container string) (io.ReadCloser, error) {
	args := m.Called(ctx, job, container)
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func TestScanner_PrepareScanJob(t *testing.T) {

	config := etc.Config{
		Operator: etc.Operator{
			StarboardNamespace: "starboard",
		},
		ScannerAquaCSP: etc.ScannerAquaCSP{
			RegistryServer: "aqua.registry.com",
			Version:        "4.6.20009",
		},
	}

	t.Run("Should prepare scan job descriptor for Deployment with two containers", func(t *testing.T) {
		namesGenerator := &mockNamesGenerator{}
		logsReader := &mockLogsReader{}

		namesGenerator.On("Next").Return("0226b891-2172-4e31-81b2-c05c2b6fd876")

		scanner := NewScanner(config, namesGenerator, logsReader, NewConverter(config.ScannerAquaCSP))

		job, err := scanner.PrepareScanJob(context.TODO(), kube.Object{
			Kind:      kube.KindDeployment,
			Name:      "nginx",
			Namespace: "dev",
		}, core.PodSpec{
			Containers: []core.Container{
				{
					Name:  "nginx",
					Image: "core.harbor.domain/library/nginx:1.16",
				},
				{
					Name:  "sidecar",
					Image: "sidecar:2.0.3",
				},
			},
		})
		require.NoError(t, err)

		assert.Equal(t, &batch.Job{
			ObjectMeta: meta.ObjectMeta{
				Name:      "0226b891-2172-4e31-81b2-c05c2b6fd876",
				Namespace: "starboard",
				Labels: map[string]string{
					"starboard.resource.kind":      "Deployment",
					"starboard.resource.name":      "nginx",
					"starboard.resource.namespace": "dev",
				},
				Annotations: map[string]string{
					"starboard.container-images": `{"nginx":"core.harbor.domain/library/nginx:1.16","sidecar":"sidecar:2.0.3"}`,
				},
			},
			Spec: batch.JobSpec{
				BackoffLimit: pointer.Int32Ptr(0),
				Template: core.PodTemplateSpec{
					Spec: core.PodSpec{
						RestartPolicy:      core.RestartPolicyNever,
						ServiceAccountName: "aqua-csp-vulnerability-scanner",
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
						Containers: []core.Container{
							{
								Name:            "nginx",
								Image:           "aqua.registry.com/scanner:4.6.20009",
								ImagePullPolicy: core.PullIfNotPresent,
								Command: []string{
									"/bin/sh",
									"-c",
									"/opt/aquasec/scannercli scan --checkonly --host $(OPERATOR_SCANNER_AQUA_CSP_HOST) --user $(OPERATOR_SCANNER_AQUA_CSP_USER) --password $(OPERATOR_SCANNER_AQUA_CSP_PASSWORD) --local core.harbor.domain/library/nginx:1.16 2> /dev/termination-log",
								},
								Env: []core.EnvVar{
									{
										Name: "OPERATOR_SCANNER_AQUA_CSP_HOST",
										ValueFrom: &core.EnvVarSource{
											SecretKeyRef: &core.SecretKeySelector{
												LocalObjectReference: core.LocalObjectReference{
													Name: "aqua-csp-vulnerability-scanner",
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
													Name: "aqua-csp-vulnerability-scanner",
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
													Name: "aqua-csp-vulnerability-scanner",
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
							},
							{
								Name:            "sidecar",
								Image:           "aqua.registry.com/scanner:4.6.20009",
								ImagePullPolicy: core.PullIfNotPresent,
								Command: []string{
									"/bin/sh",
									"-c",
									"/opt/aquasec/scannercli scan --checkonly --host $(OPERATOR_SCANNER_AQUA_CSP_HOST) --user $(OPERATOR_SCANNER_AQUA_CSP_USER) --password $(OPERATOR_SCANNER_AQUA_CSP_PASSWORD) --local sidecar:2.0.3 2> /dev/termination-log",
								},
								Env: []core.EnvVar{
									{
										Name: "OPERATOR_SCANNER_AQUA_CSP_HOST",
										ValueFrom: &core.EnvVarSource{
											SecretKeyRef: &core.SecretKeySelector{
												LocalObjectReference: core.LocalObjectReference{
													Name: "aqua-csp-vulnerability-scanner",
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
													Name: "aqua-csp-vulnerability-scanner",
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
													Name: "aqua-csp-vulnerability-scanner",
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
							},
						},
					},
				},
			},
		}, job)

		namesGenerator.AssertExpectations(t)
		logsReader.AssertExpectations(t)
	})
}
