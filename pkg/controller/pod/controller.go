package pod

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard-security-operator/pkg/action"
	core "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

type Controller struct {
	podLister  corelisters.PodLister
	podsSynced cache.InformerSynced
	action     action.Starboard
}

func NewController(
	podInformer coreinformers.PodInformer,
	action action.Starboard) (controller *Controller) {

	controller = &Controller{
		podLister:  podInformer.Lister(),
		podsSynced: podInformer.Informer().HasSynced,
		action:     action,
	}

	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: controller.podUpdated,
	})

	return
}

func (c *Controller) Run(stopCh <-chan struct{}) error {
	if ok := cache.WaitForCacheSync(stopCh, c.podsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}
	return nil
}

func (c *Controller) podUpdated(old, new interface{}) {
	var oldPod *core.Pod
	var newPod *core.Pod
	if pod, ok := old.(*core.Pod); ok {
		oldPod = pod
	}
	if pod, ok := new.(*core.Pod); ok {
		newPod = pod
	}
	if oldPod != nil && newPod != nil {
		c.processPod(oldPod, newPod)
	}
}

func (c *Controller) processPod(old, new *core.Pod) {
	if !c.action.IsPodScheduled(old, new) {
		return
	}

	klog.Infof("Processing scheduled pod: %s/%s", new.Namespace, new.Name)
	err := c.action.SubmitScanJobByPod(context.Background(), new)
	if err != nil {
		klog.Errorf("Error while submitting scan job: %v", err)
	}
}
