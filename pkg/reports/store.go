package reports

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	starboardv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type StoreInterface interface {
	Write(ctx context.Context, workload kube.Object, reports vulnerabilities.WorkloadVulnerabilities) error
	Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error)
}

type Store struct {
	client client.Client
	scheme *runtime.Scheme
}

func NewStore(client client.Client, scheme *runtime.Scheme) *Store {
	return &Store{
		client: client,
		scheme: scheme,
	}
}

func (s *Store) Write(ctx context.Context, workload kube.Object, reports vulnerabilities.WorkloadVulnerabilities) error {
	owner, err := s.getRuntimeObjectFor(ctx, workload)
	if err != nil {
		return err
	}

	for container, report := range reports {
		vulnerabilityReport := &starboardv1alpha1.Vulnerability{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf(uuid.New().String()),
				Namespace: workload.Namespace,
				Labels: labels.Set{
					kube.LabelResourceKind:      string(workload.Kind),
					kube.LabelResourceName:      workload.Name,
					kube.LabelResourceNamespace: workload.Namespace,
					kube.LabelContainerName:     container,
				},
			},
			Report: report,
		}
		err = controllerutil.SetOwnerReference(owner, vulnerabilityReport, s.scheme)
		if err != nil {
			return err
		}

		err := s.client.Create(ctx, vulnerabilityReport)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error) {
	vulnerabilityList := &starboardv1alpha1.VulnerabilityList{}

	err := s.client.List(ctx, vulnerabilityList, client.MatchingLabels{
		kube.LabelResourceKind:      string(workload.Kind),
		kube.LabelResourceNamespace: workload.Namespace,
		kube.LabelResourceName:      workload.Name,
	}, client.InNamespace(workload.Namespace))
	if err != nil {
		return nil, err
	}

	reports := make(map[string]starboardv1alpha1.VulnerabilityReport)
	for _, item := range vulnerabilityList.Items {
		if container, ok := item.Labels[kube.LabelContainerName]; ok {
			reports[container] = item.Report
		}
	}
	return reports, nil
}

func (s *Store) getRuntimeObjectFor(ctx context.Context, workload kube.Object) (metav1.Object, error) {
	var obj runtime.Object
	switch workload.Kind {
	case kube.KindPod:
		obj = &corev1.Pod{}
	case kube.KindReplicaSet:
		obj = &appsv1.ReplicaSet{}
	case kube.KindReplicationController:
		obj = &corev1.ReplicationController{}
	case kube.KindDeployment:
		obj = &appsv1.Deployment{}
	case kube.KindStatefulSet:
		obj = &appsv1.StatefulSet{}
	case kube.KindDaemonSet:
		obj = &appsv1.DaemonSet{}
	case kube.KindCronJob:
		obj = &v1beta1.CronJob{}
	case kube.KindJob:
		obj = &batchv1.Job{}
	default:
		return nil, fmt.Errorf("unknown workload kind: %s", workload.Kind)
	}
	err := s.client.Get(ctx, types.NamespacedName{Name: workload.Name, Namespace: workload.Namespace}, obj)
	if err != nil {
		return nil, err
	}
	return obj.(metav1.Object), nil
}
