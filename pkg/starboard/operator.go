package starboard

import (
	"errors"
	"fmt"
	"k8s.io/klog"

	"github.com/aquasecurity/starboard-security-operator/pkg/scanner/vulnerability/aqua"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities"
	"github.com/aquasecurity/starboard/pkg/find/vulnerabilities/trivy"
	"github.com/aquasecurity/starboard/pkg/kube"

	pods "github.com/aquasecurity/starboard/pkg/kube/pod"

	starboard "github.com/aquasecurity/starboard/pkg/generated/clientset/versioned"

	"github.com/aquasecurity/starboard-security-operator/pkg/action"

	"github.com/aquasecurity/starboard-security-operator/pkg/controller/job"
	"github.com/aquasecurity/starboard-security-operator/pkg/controller/pod"
	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

type Operator struct {
	config etc.Config
}

func NewOperator(config etc.Config) *Operator {
	return &Operator{
		config: config,
	}
}

func (o *Operator) Run() error {
	cfg, err := etc.GetKubeConfig()
	if err != nil {
		return fmt.Errorf("getting kubernetes config: %w", err)
	}

	kubeClientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("constructing kubernetes clientset: %w", err)
	}

	starboardClientset, err := starboard.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("constructing starboard clientset: %w", err)
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClientset, o.config.Operator.DefaultResync)

	pods := pods.NewPodManager(kubeClientset)

	vulnerabilityScanner, err := o.getEnabledVulnerabilityScanner(kubeClientset, pods)
	if err != nil {
		return fmt.Errorf("getting vulnerability scanner: %w", err)
	}

	starboard := action.NewStarboard(o.config, kubeClientset, starboardClientset, pods, vulnerabilityScanner)
	podController := pod.NewController(kubeInformerFactory.Core().V1().Pods(), starboard)
	jobController := job.NewController(kubeInformerFactory.Batch().V1().Jobs(), starboard)

	stopCh := make(chan struct{})
	kubeInformerFactory.Start(stopCh)

	if err = podController.Run(stopCh); err != nil {
		return fmt.Errorf("running pod controller: %w", err)
	}

	if err = jobController.Run(stopCh); err != nil {
		return fmt.Errorf("running job controller: %w", err)
	}

	<-stopCh
	return nil
}

func (o *Operator) getEnabledVulnerabilityScanner(kubeClientset kubernetes.Interface, pods *pods.Manager) (vulnerabilities.ScannerAsync, error) {
	if o.config.ScannerTrivy.Enabled && o.config.ScannerAquaCSP.Enabled {
		return nil, fmt.Errorf("invalid configuration: multiple vulnerability scanners enabled")
	}
	if !o.config.ScannerTrivy.Enabled && !o.config.ScannerAquaCSP.Enabled {
		return nil, fmt.Errorf("invalid configuration: none vulnerability scanner enabled")
	}
	if o.config.ScannerTrivy.Enabled {
		klog.Infof("Using Trivy %s as vulnerability scanner", o.config.ScannerTrivy.Version)
		return trivy.NewScanner(kube.ScannerOpts{}, kubeClientset), nil
	}
	if o.config.ScannerAquaCSP.Enabled {
		klog.Infof("Using Aqua CSP %s as vulnerability scanner", o.config.ScannerAquaCSP.Version)
		return aqua.NewScanner(o.config, pods, aqua.NewConverter(o.config.ScannerAquaCSP)), nil
	}
	return nil, errors.New("invalid configuration: unhandled vulnerability scanners config")
}
