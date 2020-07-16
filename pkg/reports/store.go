package reports

import (
	"context"
	"fmt"

	starboardv1alpha1 "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/kube"
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type StoreInterface interface {
	Write(ctx context.Context, workload kube.Object, vulnerabilities vulnerabilities.WorkloadVulnerabilities) error
	Read(ctx context.Context, workload kube.Object) (vulnerabilities.WorkloadVulnerabilities, error)
}

type Store struct {
	client client.Client
}

func NewStore(client client.Client) *Store {
	return &Store{
		client: client,
	}
}

func (s *Store) Write(ctx context.Context, workload kube.Object, reports vulnerabilities.WorkloadVulnerabilities) error {
	for container, report := range reports {
		err := s.client.Create(ctx, &starboardv1alpha1.Vulnerability{
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
		})
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
