package etc_test

import (
	"testing"

	"github.com/aquasecurity/starboard-operator/pkg/etc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperator_GetTargetNamespaces(t *testing.T) {
	testCases := []struct {
		name                     string
		operator                 etc.Operator
		expectedTargetNamespaces []string
	}{
		{
			name: "Should return all namespaces",
			operator: etc.Operator{
				TargetNamespaces: "",
			},
			expectedTargetNamespaces: []string{},
		},
		{
			name: "Should return single namespace",
			operator: etc.Operator{
				TargetNamespaces: "operators",
			},
			expectedTargetNamespaces: []string{"operators"},
		},
		{
			name: "Should return multiple namespaces",
			operator: etc.Operator{
				TargetNamespaces: "foo,bar,baz",
			},
			expectedTargetNamespaces: []string{"foo", "bar", "baz"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedTargetNamespaces, tc.operator.GetTargetNamespaces())
		})
	}
}

func TestResolveInstallMode(t *testing.T) {
	testCases := []struct {
		name string

		operatorNamespace string
		targetNamespaces  []string

		expectedInstallMode string
		expectedError       string
	}{
		{
			name:                "Should resolve OwnNamespace",
			operatorNamespace:   "operators",
			targetNamespaces:    []string{"operators"},
			expectedInstallMode: "OwnNamespace",
			expectedError:       "",
		},
		{
			name:                "Should resolve SingleNamespace",
			operatorNamespace:   "operators",
			targetNamespaces:    []string{"foo"},
			expectedInstallMode: "SingleNamespace",
			expectedError:       "",
		},
		{
			name:                "Should resolve MultiNamespace",
			operatorNamespace:   "operators",
			targetNamespaces:    []string{"foo", "bar", "baz"},
			expectedInstallMode: "MultiNamespace",
			expectedError:       "",
		},
		{
			name:                "Should resolve AllNamespaces",
			operatorNamespace:   "operators",
			targetNamespaces:    []string{},
			expectedInstallMode: "AllNamespaces",
			expectedError:       "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			installMode, err := etc.ResolveInstallMode(tc.operatorNamespace, tc.targetNamespaces)
			switch tc.expectedError {
			case "":
				require.NoError(t, err)
				assert.Equal(t, tc.expectedInstallMode, installMode)
			default:
				require.EqualError(t, err, tc.expectedError)
			}
		})
	}
}
