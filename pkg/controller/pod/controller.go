package pod

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	corev1informer "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

type Controller struct {
	kubeClientset kubernetes.Interface
	podLister     corev1lister.PodLister
	podsSynced    cache.InformerSynced
}

func NewController(
	kubeClientset kubernetes.Interface,
	podInformer corev1informer.PodInformer) (controller *Controller) {

	controller = &Controller{
		kubeClientset: kubeClientset,
		podLister:     podInformer.Lister(),
		podsSynced:    podInformer.Informer().HasSynced,
	}

	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			controller.enqueuePod(old, new)
		},
	})

	return
}

func (c *Controller) Run(stopCh <-chan struct{}) error {
	if ok := cache.WaitForCacheSync(stopCh, c.podsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}
	return nil
}

func (c *Controller) enqueuePod(old, new interface{}) {
	var oldPod *corev1.Pod
	var newPod *corev1.Pod
	if pod, ok := old.(*corev1.Pod); ok {
		oldPod = pod
	}
	if pod, ok := new.(*corev1.Pod); ok {
		newPod = pod
	}
	if oldPod != nil && newPod != nil {
		c.processPod(oldPod, newPod)
	}
}

func (c *Controller) processPod(old, new *corev1.Pod) {
	klog.Infof("Processing pod: %s/%s", new.Namespace, new.Name)
}
