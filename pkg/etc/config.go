package etc

import (
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
	StarboardNamespace  string        `env:"OPERATOR_STARBOARD_NAMESPACE" envDefault:"starboard-operator"`
	SupervisedNamespace string        `env:"OPERATOR_SUPERVISED_NAMESPACE" envDefault:"default"`
	ServiceAccount      string        `env:"OPERATOR_SERVICE_ACCOUNT" envDefault:"starboard-operator"`
	ScanJobTimeout      time.Duration `env:"OPERATOR_SCAN_JOB_TIMEOUT" envDefault:"5m"`
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

func GetConfig() (Config, error) {
	var config Config
	err := env.Parse(&config)
	return config, err
}
