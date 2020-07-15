package scanner

import (
	"encoding/json"
	"io"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/aquasecurity/starboard-security-operator/pkg/etc"

	starboard "github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
)

type Converter interface {
	Convert(imageRef string, in io.Reader) (starboard.VulnerabilityReport, error)
}

func NewConverter(config etc.ScannerAquaCSP) Converter {
	return &converter{
		config: config,
	}
}

type converter struct {
	config etc.ScannerAquaCSP
}

func (c *converter) Convert(imageRef string, in io.Reader) (starboard.VulnerabilityReport, error) {
	var aquaReport ScanReport
	err := json.NewDecoder(in).Decode(&aquaReport)
	if err != nil {
		return starboard.VulnerabilityReport{}, err
	}
	return c.convert(imageRef, aquaReport)
}

func (c *converter) convert(imageRef string, aquaReport ScanReport) (starboardReport starboard.VulnerabilityReport, err error) {
	items := make([]starboard.VulnerabilityItem, 0)

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
			items = append(items, starboard.VulnerabilityItem{
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

	registry, artifact, err := c.parseImageRef(imageRef)
	if err != nil {
		return
	}

	starboardReport = starboard.VulnerabilityReport{
		Scanner: starboard.Scanner{
			Name:    "Aqua CSP",
			Vendor:  "Aqua Security",
			Version: c.config.Version,
		},
		Registry:        registry,
		Artifact:        artifact,
		Summary:         c.toSummary(aquaReport.Summary),
		Vulnerabilities: items,
	}

	return
}

func (c *converter) toSeverity(v Vulnerability) starboard.Severity {
	switch severity := v.AquaSeverity; severity {
	case "critical":
		return starboard.SeverityCritical
	case "high":
		return starboard.SeverityHigh
	case "medium":
		return starboard.SeverityMedium
	case "low":
		return starboard.SeverityLow
	case "negligible":
		// TODO We should have severity None defined in k8s-security-crds
		return starboard.SeverityUnknown
	default:
		return starboard.SeverityUnknown
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

func (c *converter) toSummary(aquaSummary VulnerabilitySummary) starboard.VulnerabilitySummary {
	return starboard.VulnerabilitySummary{
		CriticalCount: aquaSummary.Critical,
		HighCount:     aquaSummary.High,
		MediumCount:   aquaSummary.Medium,
		LowCount:      aquaSummary.Low,
	}
}

// TODO (DRY) We have the same code for Trivy. Maybe add it to libstarboard?
func (c *converter) parseImageRef(imageRef string) (starboard.Registry, starboard.Artifact, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return starboard.Registry{}, starboard.Artifact{}, err
	}
	registry := starboard.Registry{
		URL: ref.Context().RegistryStr(),
	}
	artifact := starboard.Artifact{
		Repository: ref.Context().RepositoryStr(),
	}
	switch t := ref.(type) {
	case name.Tag:
		artifact.Tag = t.TagStr()
	case name.Digest:
		artifact.Digest = t.DigestStr()
	}

	return registry, artifact, nil
}
