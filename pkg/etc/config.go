package etc

import (
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
	StarboardNamespace string `env:"OPERATOR_STARBOARD_NAMESPACE" envDefault:"starboard"`
	Namespace          string `env:"OPERATOR_NAMESPACE" envDefault:"default"`
}

type ScannerTrivy struct {
	Enabled bool   `env:"OPERATOR_SCANNER_TRIVY_ENABLED" envDefault:"true"`
	Version string `env:"OPERATOR_SCANNER_TRIVY_VERSION" envDefault:"0.9.1"`
}

type ScannerAquaCSP struct {
	Enabled bool   `env:"OPERATOR_SCANNER_AQUA_CSP_ENABLED" envDefault:"false"`
	Version string `env:"OPERATOR_SCANNER_AQUA_CSP_VERSION" envDefault:"4.6"`
}

func GetConfig() (Config, error) {
	var config Config
	err := env.Parse(&config)
	return config, err
}
