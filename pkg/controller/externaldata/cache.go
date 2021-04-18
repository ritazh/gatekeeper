package externaldata

import (
	"fmt"
	"sync"
)

type ProviderCache struct {
	cache map[string]string
	mux   sync.RWMutex
}

func NewCache() *ProviderCache {
	return &ProviderCache{
		cache: make(map[string]string),
	}
}

func (c *ProviderCache) Get(key string) (string, error) {
	if v, ok := c.cache[key]; ok {
		return v, nil
	}
	return "", fmt.Errorf("key is not found in cache")
}

func (c *ProviderCache) Upsert(key string, value string) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.cache[key] = value

	return nil
}

func (c *ProviderCache) Remove(key string) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	delete(c.cache, key)

	return nil
}
