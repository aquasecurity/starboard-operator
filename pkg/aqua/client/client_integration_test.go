package client

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClient(t *testing.T) {
	if testing.Short() {
		t.Skip("Run this test manually")
	}

	c := NewClient("http://aqua.domain", Authorization{
		Basic: &UsernameAndPassword{"administrator", "Password12345"}})

	t.Run("Should list registries", func(t *testing.T) {
		registries, err := c.Registries().List()
		require.NoError(t, err)
		for _, registry := range registries {
			t.Logf("registry: %+v", registry)
		}
	})

	t.Run("Should get vulnerabilities from Ad Hoc Scans registry", func(t *testing.T) {
		resp, err := c.Images().Vulnerabilities("Ad Hoc Scans", "core.harbor.domain/library/nginx", "1.16")
		require.NoError(t, err)
		for _, vulnerability := range resp.Results {
			t.Logf("vulnerability: %+v", vulnerability)
		}
	})

	t.Run("Should get vulnerabilities from Harbor registry", func(t *testing.T) {
		vr, err := c.Images().Vulnerabilities("Harbor", "library/nginx", "1.16")
		require.NoError(t, err)
		for _, vulnerability := range vr.Results {
			t.Logf("vulnerability: %+v", vulnerability)
		}
	})

}
