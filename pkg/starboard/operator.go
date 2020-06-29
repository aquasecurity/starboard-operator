package starboard

import (
	"fmt"

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

	starboard := action.NewStarboard(o.config, kubeClientset, starboardClientset)
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
