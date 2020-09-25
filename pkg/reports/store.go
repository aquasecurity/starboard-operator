package reports

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/aquasecurity/starboard-operator/pkg/resources"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var log = ctrl.Log.WithName("reports").WithName("store")

type StoreInterface interface {
	WriteAll(ctx context.Context, workload kube.Object, reports vulnerabilities.WorkloadVulnerabilities) error
	Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error)
	HasVulnerabilityReports(ctx context.Context, owner kube.Object, containerImages kube.ContainerImages) (bool, error)
	GetOwnerOf(ctx context.Context, owned metav1.Object) (*metav1.Object, *schema.GroupVersionKind, error)
	GetControllerOf(ctx context.Context, owned metav1.Object) (*metav1.Object, *schema.GroupVersionKind, error)
}

type store struct {
	client client.Client
	scheme *runtime.Scheme
}

func NewStore(client client.Client, scheme *runtime.Scheme) StoreInterface {
	return &store{
		client: client,
		scheme: scheme,
	}
}

func (s *store) WriteAll(ctx context.Context, workload kube.Object, reports vulnerabilities.WorkloadVulnerabilities) error {
	owner, err := s.getRuntimeObjectFor(ctx, workload)
	if err != nil {
		return err
	}

	for containerName, report := range reports {
		reportName := fmt.Sprintf("%s-%s-%s", strings.ToLower(string(workload.Kind)),
			workload.Name, containerName)

		vulnerabilityReport := &starboardv1alpha1.VulnerabilityReport{}

		err := s.client.Get(ctx, types.NamespacedName{Name: reportName, Namespace: workload.Namespace}, vulnerabilityReport)

		if errors.IsNotFound(err) {
			vulnerabilityReport = &starboardv1alpha1.VulnerabilityReport{
				ObjectMeta: metav1.ObjectMeta{
					Name:      reportName,
					Namespace: workload.Namespace,
					Labels: labels.Set{
						kube.LabelResourceKind:      string(workload.Kind),
						kube.LabelResourceName:      workload.Name,
						kube.LabelResourceNamespace: workload.Namespace,
						kube.LabelContainerName:     containerName,
					},
				},
				Report: report,
			}
			err = controllerutil.SetOwnerReference(owner, vulnerabilityReport, s.scheme)
			if err != nil {
				return err
			}
			log.V(1).Info("Creating VulnerabilityReport", "name", reportName, "owner", workload)
			err = s.client.Create(ctx, vulnerabilityReport)
			if err != nil {
				return err
			}
			return nil
		} else if err != nil {
			return err
		}

		log.V(1).Info("Updating VulnerabilityReport", "name", reportName, "owner", workload)
		copied := vulnerabilityReport.DeepCopy()
		copied.Report = report
		err = s.client.Update(ctx, copied)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *store) Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error) {
	vulnerabilityList := &starboardv1alpha1.VulnerabilityReportList{}

	err := s.client.List(ctx, vulnerabilityList, client.MatchingLabels{
		kube.LabelResourceKind:      string(workload.Kind),
		kube.LabelResourceNamespace: workload.Namespace,
		kube.LabelResourceName:      workload.Name,
	}, client.InNamespace(workload.Namespace))
	if err != nil {
		return nil, err
	}

	reports := make(map[string]starboardv1alpha1.VulnerabilityScanResult)
	for _, item := range vulnerabilityList.Items {
		if container, ok := item.Labels[kube.LabelContainerName]; ok {
			reports[container] = item.Report
		}
	}
	return reports, nil
}

func (s *store) GetOwnerOf(ctx context.Context, owned metav1.Object) (*metav1.Object, *schema.GroupVersionKind, error) {
	ownerRef := resources.GetOwnerOf(owned)
	if ownerRef == nil {
		return nil, nil, nil
	}

	var tmp runtime.Object
	var err error

	tmp, err = s.NewObjectForKind(ownerRef.Kind)
	if err != nil {
		return nil, nil, err
	}

	err = s.client.Get(ctx, types.NamespacedName{Name: ownerRef.Name, Namespace: owned.GetNamespace()}, tmp)
	if err != nil {
		return nil, nil, err
	}

	owner := tmp.(metav1.Object)

	gvk, err := kube.GVKForObject(tmp, s.scheme)
	if err != nil {
		return nil, nil, err
	}
	return &owner, &gvk, nil
}

func (s *store) GetControllerOf(ctx context.Context, owned metav1.Object) (*metav1.Object, *schema.GroupVersionKind, error) {
	controllerRef := metav1.GetControllerOf(owned)
	if controllerRef == nil {
		return nil, nil, nil
	}

	var tmp runtime.Object
	var err error

	tmp, err = s.NewObjectForKind(controllerRef.Kind)
	if err != nil {
		return nil, nil, err
	}

	err = s.client.Get(ctx, types.NamespacedName{Name: controllerRef.Name, Namespace: owned.GetNamespace()}, tmp)
	if err != nil {
		return nil, nil, err
	}
	controller := tmp.(metav1.Object)

	gvk, err := kube.GVKForObject(tmp, s.scheme)
	if err != nil {
		return nil, nil, err
	}

	return &controller, &gvk, nil
}

func (s *store) NewObjectForKind(kind string) (runtime.Object, error) {
	var obj runtime.Object

	switch kube.Kind(kind) {
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
		return nil, fmt.Errorf("unknown workload kind: %s", kind)
	}
	return obj, nil
}

func (s *store) getRuntimeObjectFor(ctx context.Context, workload kube.Object) (metav1.Object, error) {
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

func (s *store) HasVulnerabilityReports(ctx context.Context, owner kube.Object, containerImages kube.ContainerImages) (bool, error) {
	vulnerabilityReports, err := s.Read(ctx, owner)
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
