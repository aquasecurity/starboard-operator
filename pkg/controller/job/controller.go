package job

import (
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	batchv1informer "k8s.io/client-go/informers/batch/v1"
	"k8s.io/client-go/kubernetes"
	batchv1lister "k8s.io/client-go/listers/batch/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

type Controller struct {
	kubeClientset kubernetes.Interface
	jobLister     batchv1lister.JobLister
	jobsSynced    cache.InformerSynced
}

func NewController(
	kubeClientset kubernetes.Interface,
	jobInformer batchv1informer.JobInformer) (controller *Controller) {

	controller = &Controller{
		kubeClientset: kubeClientset,
		jobLister:     jobInformer.Lister(),
		jobsSynced:    jobInformer.Informer().HasSynced,
	}

	jobInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueJob(new)
		},
	})

	return
}

func (c *Controller) Run(stopCh <-chan struct{}) error {
	if ok := cache.WaitForCacheSync(stopCh, c.jobsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}
	return nil
}

func (c *Controller) enqueueJob(new interface{}) {
	if pod, ok := new.(*batchv1.Job); ok {
		c.processJob(pod)
	}
}

func (c *Controller) processJob(new *batchv1.Job) {
	klog.Infof("Processing job: %s/%s", new.Namespace, new.Name)
}
