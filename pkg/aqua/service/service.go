package service

import (
	"github.com/aquasecurity/starboard-security-operator/pkg/aqua/client"
	"github.com/aquasecurity/starboard/pkg/apis/aquasecurity/v1alpha1"
	"github.com/google/go-containerregistry/pkg/name"
	"strings"
)

type Service struct {
	clientset client.Clientset
}

func NewService(clientset client.Clientset) *Service {
	return &Service{
		clientset: clientset,
	}
}

func (s *Service) GetVulnerabilityReportByImageRef(imageRef string) (report v1alpha1.VulnerabilityReport, err error) {
	registryServer, repository, tag, err := s.parseImageRef(imageRef)
	if err != nil {
		return
	}

	registryName, err := s.getRegistryName(registryServer)
	if err != nil {
		return
	}
	x := repository[strings.LastIndex(repository, "/")+1:]
	vulnerabilitiesResponse, err := s.clientset.Images().Vulnerabilities(registryName, x, tag)
	if err != nil {
		return
	}

	report = s.convert(vulnerabilitiesResponse)
	return
}

func (s *Service) convert(response client.VulnerabilitiesResponse) v1alpha1.VulnerabilityReport {
	return v1alpha1.VulnerabilityReport{}
}

func (s *Service) getRegistryName(registryServer string) (registryName string, err error) {
	registries, err := s.clientset.Registries().List()
	if err != nil {
		return
	}
	for _, registry := range registries {
		for _, prefix := range registry.Prefixes {
			if registryServer == prefix {
				registryName = registry.Name
				return
			}
		}
	}
	registryName = "Ad Hoc Scans"
	return
}

func (s *Service) parseImageRef(imageRef string) (registry string, repository string, tag string, err error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return
	}
	registry = ref.Context().RegistryStr()
	repository = ref.Context().RepositoryStr()
	tag = ref.Identifier()

	return
}
