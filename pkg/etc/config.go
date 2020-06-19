package etc

import (
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	"github.com/caarlos0/env/v6"
)

type Config struct {
	Operator Operator
}

type Operator struct {
	StarboardNamespace string `env:"OPERATOR_STARBOARD_NAMESPACE" endDefault:"starboard"`
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
