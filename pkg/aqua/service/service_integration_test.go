package service

import (
	"github.com/aquasecurity/starboard-security-operator/pkg/aqua/client"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestService(t *testing.T) {
	if testing.Short() {
		t.Skip("Integration test")
	}

	service := NewService(client.NewClient("http://aqua.domain", client.Authorization{
		Basic: &client.UsernameAndPassword{Username: "administrator", Password: "Password12345"}}))
	report, err := service.GetVulnerabilityReportByImageRef("mongo:4.2.8")
	require.NoError(t, err)
	t.Logf("report: %v", report)
}
