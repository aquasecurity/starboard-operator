package job

import (
	"context"
	"fmt"

	"github.com/aquasecurity/starboard-security-operator/pkg/action"

	batch "k8s.io/api/batch/v1"
	batchinformers "k8s.io/client-go/informers/batch/v1"
	batchlisters "k8s.io/client-go/listers/batch/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

type Controller struct {
	jobLister  batchlisters.JobLister
	jobsSynced cache.InformerSynced
	action     action.Starboard
}

func NewController(
	jobInformer batchinformers.JobInformer,
	action action.Starboard) (controller *Controller) {

	controller = &Controller{
		jobLister:  jobInformer.Lister(),
		jobsSynced: jobInformer.Informer().HasSynced,
		action:     action,
	}

	jobInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: controller.jobUpdated,
	})

	return
}

func (c *Controller) Run(stopCh <-chan struct{}) error {
	if ok := cache.WaitForCacheSync(stopCh, c.jobsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}
	return nil
}

func (c *Controller) jobUpdated(_, new interface{}) {
	if pod, ok := new.(*batch.Job); ok {
		c.processJob(nil, pod)
	}
}

func (c *Controller) processJob(old, new *batch.Job) {
	if !c.action.IsScanJobProcessable(old, new) {
		return
	}

	klog.Infof("Processing job: %s/%s", new.Namespace, new.Name)
	err := c.action.ProcessCompleteScanJob(context.Background(), new)
	if err != nil {
		klog.Errorf("Error while processing job: %v", err)
	}
}
