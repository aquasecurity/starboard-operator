package etc

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v6"
)

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	Operator       Operator
	ScannerAquaCSP ScannerAquaCSP
	ScannerTrivy   ScannerTrivy
}

type Operator struct {
	Namespace        string        `env:"OPERATOR_NAMESPACE"`
	TargetNamespaces string        `env:"OPERATOR_TARGET_NAMESPACES"`
	ServiceAccount   string        `env:"OPERATOR_SERVICE_ACCOUNT" envDefault:"starboard-operator"`
	ScanJobTimeout   time.Duration `env:"OPERATOR_SCAN_JOB_TIMEOUT" envDefault:"5m"`
}

type ScannerTrivy struct {
	Enabled bool   `env:"OPERATOR_SCANNER_TRIVY_ENABLED" envDefault:"true"`
	Version string `env:"OPERATOR_SCANNER_TRIVY_VERSION" envDefault:"0.11.0"`
}

type ScannerAquaCSP struct {
	Enabled  bool   `env:"OPERATOR_SCANNER_AQUA_CSP_ENABLED" envDefault:"false"`
	Version  string `env:"OPERATOR_SCANNER_AQUA_CSP_VERSION" envDefault:"5.0"`
	Host     string `env:"OPERATOR_SCANNER_AQUA_CSP_HOST"`
	Username string `env:"OPERATOR_SCANNER_AQUA_CSP_USERNAME"`
	Password string `env:"OPERATOR_SCANNER_AQUA_CSP_PASSWORD"`
}

func GetOperatorConfig() (Config, error) {
	var config Config
	err := env.Parse(&config)
	return config, err
}

// GetOperatorNamespace returns the namespace the operator should be running in.
func (c Operator) GetOperatorNamespace() (string, error) {
	namespace := c.Namespace
	if namespace != "" {
		return namespace, nil
	}
	return "", fmt.Errorf("%s must be set", "OPERATOR_NAMESPACE")
}

// GetTargetNamespaces returns namespaces the operator should be watching for changes.
func (c Operator) GetTargetNamespaces() []string {
	namespaces := c.TargetNamespaces
	if namespaces != "" {
		return strings.Split(namespaces, ",")
	}
	return []string{}
}

// ResolveInstallMode resolves install mode as defined by the OLM (Operator Lifecycle Manager).
func ResolveInstallMode(operatorNamespace string, targetNamespaces []string) (string, error) {
	if len(targetNamespaces) == 1 && operatorNamespace == targetNamespaces[0] {
		return "OwnNamespace", nil
	}
	if len(targetNamespaces) == 1 && operatorNamespace != targetNamespaces[0] {
		return "SingleNamespace", nil
	}
	if len(targetNamespaces) > 1 {
		return "MultiNamespace", nil
	}
	if len(targetNamespaces) == 0 {
		return "AllNamespaces", nil
	}
	return "", errors.New("unrecognized install mode")
}
