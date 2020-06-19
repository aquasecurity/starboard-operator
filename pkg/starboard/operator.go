package starboard

import (
	"fmt"
	"time"

	"github.com/aquasecurity/starboard-security-operator/pkg/controller/job"
	"github.com/aquasecurity/starboard-security-operator/pkg/controller/pod"
	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
)

type Operator struct {
}

func NewOperator() *Operator {
	return &Operator{}
}

func (o *Operator) Run() error {
	cfg, err := etc.GetKubeConfig()

	kubeClientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("builiding kubernetes clientset: %w", err)
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClientset, time.Minute*10)

	podController := pod.NewController(kubeClientset, kubeInformerFactory.Core().V1().Pods())
	jobController := job.NewController(kubeClientset, kubeInformerFactory.Batch().V1().Jobs())

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
