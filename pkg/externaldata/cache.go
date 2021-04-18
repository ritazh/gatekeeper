package externaldata

import (
	"fmt"
	"sync"

	"github.com/open-policy-agent/gatekeeper/pkg/logging"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	log = logf.Log.WithName("controller").WithValues(logging.Process, "externaldata_controller")
)

type ProviderCache struct {
	Cache map[string]string
	mux   sync.RWMutex
}

func NewCache() *ProviderCache {
	return &ProviderCache{
		Cache: make(map[string]string),
	}
}

func (c *ProviderCache) Get(key string) (string, error) {
	log.Info("***", "cache", c.Cache)
	if v, ok := c.Cache[key]; ok {
		return v, nil
	}
	return "", fmt.Errorf("key is not found in cache")
}

func (c *ProviderCache) Upsert(key string, value string) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.Cache[key] = value

	return nil
}

func (c *ProviderCache) Remove(key string) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	delete(c.Cache, key)

	return nil
}
