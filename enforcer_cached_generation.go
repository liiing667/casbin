// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

import (
	"sync"
	"sync/atomic"

	"github.com/casbin/casbin/v3/persist/cache"
)

// generationCache tags every cached decision with the generation it was
// computed for. A cache hit is only served when the entry's generation matches
// the current one, so a decision can never outlive the policy or role links it
// was based on. The enforcer serializes cache.clear against Enforce, so cache
// access itself needs no extra locking here.
type generationCache struct {
	// generation is accessed atomically, so it stays first to be 64-bit
	// aligned on 32-bit platforms.
	generation uint64
	cache      cache.Cache
	items      sync.Map // string -> uint64 generation of the cached decision
}

func newGenerationCache(inner cache.Cache) *generationCache {
	return &generationCache{
		generation: 1,
		cache:      inner,
	}
}

// withGeneration keeps the current generation when the backing cache is
// replaced, so swapping the cache implementation does not resurrect decisions
// from an older generation.
func (c *generationCache) withGeneration(generation uint64) *generationCache {
	atomic.StoreUint64(&c.generation, generation)
	return c
}

// currentGeneration returns the generation that fresh decisions belong to.
func (c *generationCache) currentGeneration() uint64 {
	return atomic.LoadUint64(&c.generation)
}

// getForGeneration returns the cached decision only when its tag matches the
// snapshot generation. Stale and expired entries behave as cache misses.
func (c *generationCache) getForGeneration(snapshot uint64, key string) (bool, error) {
	if c.currentGeneration() != snapshot {
		return false, cache.ErrNoSuchKey
	}
	storedGeneration, ok := c.items.Load(key)
	if !ok || storedGeneration.(uint64) != snapshot {
		return false, cache.ErrNoSuchKey
	}
	return c.cache.Get(key)
}

// set stores a decision together with a generation snapshot. The write is
// skipped when the cache generation has moved on while the decision was being
// computed.
func (c *generationCache) set(snapshot uint64, key string, value bool, extra ...interface{}) error {
	if snapshot != c.currentGeneration() {
		return nil
	}
	if err := c.cache.Set(key, value, extra...); err != nil {
		return err
	}
	c.items.Store(key, snapshot)
	return nil
}

// clear drops every cached decision and advances the generation. Entries left
// behind by a non-cooperative cache implementation are rejected on read by
// the generation check, so generations can never mix.
func (c *generationCache) clear() error {
	atomic.AddUint64(&c.generation, 1)
	if err := c.cache.Clear(); err != nil {
		return err
	}
	c.items.Range(func(key, _ interface{}) bool {
		c.items.Delete(key)
		return true
	})
	return nil
}
