module github.com/aquasecurity/starboard-security-operator

go 1.14

require (
	github.com/aquasecurity/starboard v0.2.6
	github.com/caarlos0/env/v6 v6.2.2
	github.com/go-logr/logr v0.1.0
	github.com/google/go-containerregistry v0.1.1
	github.com/google/uuid v1.1.1
	github.com/onsi/ginkgo v1.14.0
	github.com/onsi/gomega v1.10.1
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.5.1
	k8s.io/api v0.19.0-alpha.3
	k8s.io/apimachinery v0.19.0-alpha.3
	k8s.io/client-go v0.19.0-alpha.3
	k8s.io/klog v1.0.0
	k8s.io/utils v0.0.0-20200603063816-c1c6865ac451
	sigs.k8s.io/controller-runtime v0.6.2
)

replace (
	github.com/aquasecurity/starboard => /Users/dpacak/go/src/github.com/aquasecurity/starboard
	k8s.io/api => k8s.io/api v0.18.4
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.18.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.4
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.18.4
	k8s.io/client-go => k8s.io/client-go v0.18.4
	k8s.io/code-generator => k8s.io/code-generator v0.18.4
	k8s.io/metrics => k8s.io/metrics v0.18.4
)
