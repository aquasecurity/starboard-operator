package aqua

import (
	"encoding/json"
	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
	"io"

	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Converter interface {
	Convert(in io.Reader) (v1alpha1.VulnerabilityReport, error)
}

func NewConverter(config etc.ScannerAquaCSP) Converter {
	return &converter{
		config: config,
	}
}

type converter struct {
	config etc.ScannerAquaCSP
}

func (c *converter) Convert(in io.Reader) (v1alpha1.VulnerabilityReport, error) {
	var aquaReport ScanReport
	err := json.NewDecoder(in).Decode(&aquaReport)
	if err != nil {
		return v1alpha1.VulnerabilityReport{}, err
	}
	return c.convert(aquaReport), nil
}

func (c *converter) convert(aquaReport ScanReport) (starboardReport v1alpha1.VulnerabilityReport) {
	var items []v1alpha1.VulnerabilityItem

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
				Severity:         c.toSeverity(vln),
				Description:      vln.Description,
				Links:            c.toLinks(vln),
			})
		}
	}
	starboardReport = v1alpha1.VulnerabilityReport{
		Vulnerabilities: items,
		Scanner: v1alpha1.Scanner{
			Name:    "Aqua CSP",
			Vendor:  "Aqua Security",
			Version: c.config.Version,
		},
		Summary: c.toSummary(aquaReport.Summary),
	}

	return
}

func (c *converter) toSeverity(v Vulnerability) v1alpha1.Severity {
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

func (c *converter) toLinks(v Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	if v.VendorURL != "" {
		links = append(links, v.VendorURL)
	}
	return links
}

func (c *converter) toSummary(aquaSummary VulnerabilitySummary) v1alpha1.VulnerabilitySummary {
	return v1alpha1.VulnerabilitySummary{
		CriticalCount: aquaSummary.Critical,
		HighCount:     aquaSummary.High,
		MediumCount:   aquaSummary.Medium,
		LowCount:      aquaSummary.Low,
	}
}
