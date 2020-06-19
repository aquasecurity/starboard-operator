package main

import (
	"github.com/aquasecurity/starboard-security-operator/pkg/etc"
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
	config, err := etc.GetConfig()
	if err != nil {
		return err
	}
	operator := starboard.NewOperator(config.Operator)
	err = operator.Run()
	if err != nil {
		return err
	}
	return nil
}
