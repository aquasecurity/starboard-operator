package etc

import (
	"os"
	"path/filepath"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	"github.com/caarlos0/env/v6"
)

type Config struct {
	Operator       Operator
	ScannerAquaCSP ScannerAquaCSP
	ScannerTrivy   ScannerTrivy
}

type Operator struct {
	StarboardNamespace string        `env:"OPERATOR_STARBOARD_NAMESPACE" envDefault:"starboard"`
	DefaultResync      time.Duration `env:"OPERATOR_STARBOARD_DEFAULT_RESYNC" envDefault:"10m"`
}

type ScannerTrivy struct {
	Version string `env:"OPERATOR_SCANNER_TRIVY_VERSION" envDefault:"0.9.1"`
}

type ScannerAquaCSP struct {
	Version        string `env:"OPERATOR_SCANNER_AQUA_CSP_VERSION" envDefault:"4.6"`
	RegistryServer string `env:"OPERATOR_SCANNER_AQUA_REGISTRY_SERVER" envDefault:"aquasec.azurecr.io"`
}

func GetConfig() (Config, error) {
	var config Config
	err := env.Parse(&config)
	return config, err
}

func GetKubeConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.BuildConfigFromFlags("", defaultKubeConfigPath())
		if err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func defaultKubeConfigPath() string {
	fname := os.Getenv("KUBECONFIG")
	if fname != "" {
		return fname
	}
	home, err := os.UserHomeDir()
	if err != nil {
		klog.Warningf("Failed to get home directory: %v", err)
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}
