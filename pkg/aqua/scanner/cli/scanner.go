package cli

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/aquasecurity/starboard-security-operator/pkg/aqua/client"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
)

type Scanner struct {
	baseURL     string
	credentials client.UsernameAndPassword
}

func NewScanner(baseURL string, credentials client.UsernameAndPassword) *Scanner {
	return &Scanner{
		baseURL:     baseURL,
		credentials: credentials,
	}
}

func (s *Scanner) Scan(imageRef string) (report v1alpha1.VulnerabilityReport, err error) {
	args := []string{
		"scan",
		"--checkonly",
		"--dockerless",
		fmt.Sprintf("--host=%s", s.baseURL),
		fmt.Sprintf("--user=%s", s.credentials.Username),
		fmt.Sprintf("--password=%s", s.credentials.Password),
		"--local",
		imageRef,
	}
	command := exec.Command("scannercli", args...)

	out, err := command.Output()
	if err != nil {
		err = fmt.Errorf("running scannercli: %w", err)
		return
	}
	var aquaReport ScanReport
	err = json.Unmarshal(out, &aquaReport)
	if err != nil {
		return
	}
	return s.convert(imageRef, aquaReport)
}

func (s *Scanner) convert(imageRef string, aquaReport ScanReport) (report v1alpha1.VulnerabilityReport, err error) {
	items := make([]v1alpha1.VulnerabilityItem, 0)

	for _, resourceScan := range aquaReport.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			var pkg string
			switch resourceScan.Resource.Type {
			case Library:
				pkg = resourceScan.Resource.Path
			case Package:
				pkg = resourceScan.Resource.Name
			default:
				pkg = resourceScan.Resource.Name
			}
			items = append(items, v1alpha1.VulnerabilityItem{
				VulnerabilityID:  vln.Name,
				Resource:         pkg,
				InstalledVersion: resourceScan.Resource.Version,
				FixedVersion:     vln.FixVersion,
				Severity:         s.toSeverity(vln),
				Description:      vln.Description,
				Links:            s.toLinks(vln),
			})
		}
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return
	}

	artifact := v1alpha1.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}

	report = v1alpha1.VulnerabilityReport{
		Scanner: v1alpha1.Scanner{
			Name:   "Aqua CSP",
			Vendor: "Aqua Security",
			//Version: c.config.Version,
		},
		Registry: v1alpha1.Registry{
			URL: ref.Context().RegistryStr(),
		},
		Artifact:        artifact,
		Summary:         s.toSummary(aquaReport.Summary),
		Vulnerabilities: items,
	}
	return
}

func (s *Scanner) toSeverity(v Vulnerability) v1alpha1.Severity {
	switch severity := v.AquaSeverity; severity {
	case "critical":
		return v1alpha1.SeverityCritical
	case "high":
		return v1alpha1.SeverityHigh
	case "medium":
		return v1alpha1.SeverityMedium
	case "low":
		return v1alpha1.SeverityLow
	case "negligible":
		// TODO We should have severity None defined in k8s-security-crds
		return v1alpha1.SeverityUnknown
	default:
		return v1alpha1.SeverityUnknown
	}
}

func (s *Scanner) toLinks(v Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	if v.VendorURL != "" {
		links = append(links, v.VendorURL)
	}
	return links
}

func (s *Scanner) toSummary(aquaSummary VulnerabilitySummary) v1alpha1.VulnerabilitySummary {
	return v1alpha1.VulnerabilitySummary{
		CriticalCount: aquaSummary.Critical,
		HighCount:     aquaSummary.High,
		MediumCount:   aquaSummary.Medium,
		LowCount:      aquaSummary.Low,
	}
}
