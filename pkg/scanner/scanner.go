package scanner

import (
	"io"
	"time"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"

	"github.com/aquasecurity/starboard/pkg/kube"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// Options are arguments passed to VulnerabilityScanner.NewScanJob constructor.
type Options struct {
	// Namespace the namespace to run the scan Job in.
	Namespace string
	// ServiceAccountName the name of the Service Account to run the Pod controlled by the scan Job.
	ServiceAccountName string
	// ScanJobTimeout scan job timeout.
	ScanJobTimeout time.Duration
}

// VulnerabilityScanner defines vulnerability scanner interface.
//
// NewScanJob constructs a new Job descriptor, which can be sent to Kubernetes API and scheduled to scan
// the specified Kubernetes workload with the given Pod descriptor and Options.
//
type VulnerabilityScanner interface {
	NewScanJob(workload kube.Object, spec corev1.PodSpec, options Options) (*batchv1.Job, error)
	ParseVulnerabilityReport(imageRef string, logsReader io.ReadCloser) (v1alpha1.VulnerabilityScanResult, error)
}
