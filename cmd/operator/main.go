package main

import (
	"github.com/aquasecurity/starboard-security-operator/pkg/starboard"
	"k8s.io/klog"
)

func main() {
	defer klog.Flush()

	if err := run(); err != nil {
		klog.Errorf("Error: %v", err)
	}
}

func run() error {
	operator := starboard.NewOperator()
	err := operator.Run()
	if err != nil {
		return err
	}
	return nil
}
