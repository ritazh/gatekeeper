package gator

import (
	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	//"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/local"
	"github.com/open-policy-agent/gatekeeper/pkg/target"
	"github.com/open-policy-agent/gatekeeper/pkg/wasm"
)

func NewOPAClient() (Client, error) {
	// driver, err := local.New(local.Tracing(false))
	// if err != nil {
	// 	return nil, err
	// }

	driver := wasm.NewDriver()

	c, err := constraintclient.NewClient(constraintclient.Targets(&target.K8sValidationTarget{}), constraintclient.Driver(driver))
	if err != nil {
		return nil, err
	}

	return c, nil
}
