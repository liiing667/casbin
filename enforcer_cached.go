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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v3/persist/cache"
)

// CachedEnforcer wraps Enforcer and provides decision cache.
type CachedEnforcer struct {
	*Enforcer
	expireTime  time.Duration
	cache       *generationCache
	enableCache int32
	// barrier makes a policy or role-link change (together with its cache
	// invalidation) atomic relative to Enforce. Enforce holds it as a read
	// lock, so concurrent-safe cache backends still serve parallel cache hits.
	barrier sync.RWMutex
	// concurrentCache reports whether the backing cache is safe for concurrent
	// use; a plain map cache is only accessed while barrier is held exclusively.
	concurrentCache bool
}

type CacheableParam interface {
	GetCacheKey() string
}

// NewCachedEnforcer creates a cached enforcer via file or DB.
func NewCachedEnforcer(params ...interface{}) (*CachedEnforcer, error) {
	e := &CachedEnforcer{}
	var err error
	e.Enforcer, err = NewEnforcer(params...)
	if err != nil {
		return nil, err
	}

	e.enableCache = 1
	innerCache, _ := cache.NewConcurrentCache(cache.DefaultConcurrentCacheSize)
	e.cache = newGenerationCache(innerCache)
	e.concurrentCache = true
	return e, nil
}

// EnableCache determines whether to enable cache on Enforce(). When enableCache is enabled, cached result (true | false) will be returned for previous decisions.
func (e *CachedEnforcer) EnableCache(enableCache bool) {
	var enabled int32
	if enableCache {
		enabled = 1
	}
	atomic.StoreInt32(&e.enableCache, enabled)
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
// if rvals is not string , ignore the cache.
func (e *CachedEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	if atomic.LoadInt32(&e.enableCache) == 0 || !e.enabled {
		return e.Enforcer.Enforce(rvals...)
	}

	key, ok := e.getKey(rvals...)
	if !ok {
		return e.Enforcer.Enforce(rvals...)
	}

	e.lockEnforceRead()
	defer e.unlockEnforceRead()

	snapshot := e.cache.currentGeneration()
	if res, err := e.cache.getForGeneration(snapshot, key); err == nil {
		return res, nil
	} else if err != cache.ErrNoSuchKey {
		return res, err
	}

	res, err := e.Enforcer.Enforce(rvals...)
	if err != nil {
		return false, err
	}
	// The barrier guarantees the generation cannot change while this decision
	// is being computed, so the result is safe to tag with the snapshot.
	if err := e.cache.set(snapshot, key, res, e.expireTime); err != nil {
		return res, err
	}
	return res, nil
}

// lockEnforceRead takes the barrier read lock for a concurrent-safe backend,
// or an exclusive lock for a backend that is not safe for concurrent use.
func (e *CachedEnforcer) lockEnforceRead() {
	if e.concurrentCache {
		e.barrier.RLock()
		return
	}
	e.barrier.Lock()
}

func (e *CachedEnforcer) unlockEnforceRead() {
	if e.concurrentCache {
		e.barrier.RUnlock()
		return
	}
	e.barrier.Unlock()
}

// mutate runs a policy or role-link change and, after it has finished, advances
// the cache generation so every cached decision from the previous state is
// discarded. The write lock makes the change and the invalidation atomic.
func (e *CachedEnforcer) mutate(fn func() (bool, error)) (bool, error) {
	e.barrier.Lock()
	defer e.barrier.Unlock()
	affected, err := fn()
	if err != nil {
		return affected, err
	}
	if err := e.invalidateCache(); err != nil {
		return affected, err
	}
	return affected, nil
}

// mutateErr is the error-returning variant of mutate, used by LoadPolicy.
func (e *CachedEnforcer) mutateErr(fn func() error) error {
	e.barrier.Lock()
	defer e.barrier.Unlock()
	if err := fn(); err != nil {
		return err
	}
	return e.invalidateCache()
}

func (e *CachedEnforcer) invalidateCache() error {
	if atomic.LoadInt32(&e.enableCache) == 0 {
		return nil
	}
	return e.cache.clear()
}

func (e *CachedEnforcer) LoadPolicy() error {
	return e.mutateErr(e.Enforcer.LoadPolicy)
}

func (e *CachedEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.AddPolicy(params...)
	})
}

func (e *CachedEnforcer) AddPolicies(rules [][]string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.AddPolicies(rules)
	})
}

func (e *CachedEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemovePolicy(params...)
	})
}

func (e *CachedEnforcer) RemovePolicies(rules [][]string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemovePolicies(rules)
	})
}

func (e *CachedEnforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
	})
}

func (e *CachedEnforcer) UpdatePolicy(oldPolicy []string, newPolicy []string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.UpdatePolicy(oldPolicy, newPolicy)
	})
}

func (e *CachedEnforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.AddGroupingPolicy(params...)
	})
}

func (e *CachedEnforcer) RemoveGroupingPolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemoveGroupingPolicy(params...)
	})
}

func (e *CachedEnforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemoveFilteredGroupingPolicy(fieldIndex, fieldValues...)
	})
}

func (e *CachedEnforcer) SetExpireTime(expireTime time.Duration) {
	e.expireTime = expireTime
}

// SetCache replaces the decision cache. A cache that is not safe for concurrent use is only accessed under an exclusive lock.
func (e *CachedEnforcer) SetCache(c cache.Cache) {
	e.barrier.Lock()
	defer e.barrier.Unlock()
	e.cache = newGenerationCache(c).withGeneration(e.cache.currentGeneration())
	e.concurrentCache = isConcurrentCache(c)
}

func isConcurrentCache(c cache.Cache) bool {
	switch c.(type) {
	case *cache.ConcurrentCache, *cache.SyncCache:
		return true
	default:
		return false
	}
}

func (e *CachedEnforcer) getKey(params ...interface{}) (string, bool) {
	return GetCacheKey(params...)
}

// InvalidateCache deletes all the existing cached decisions.
func (e *CachedEnforcer) InvalidateCache() error {
	e.barrier.Lock()
	defer e.barrier.Unlock()
	return e.cache.clear()
}

type cacheKeyPart struct {
	kind  byte
	value string
}

// GetCacheKey length-prefixes each part so that different requests never share a key.
func GetCacheKey(params ...interface{}) (string, bool) {
	var partsBuf [8]cacheKeyPart
	parts := partsBuf[:0]
	size := 0
	for _, param := range params {
		var part cacheKeyPart
		switch typedParam := param.(type) {
		case string:
			part = cacheKeyPart{kind: 's', value: typedParam}
		case CacheableParam:
			part = cacheKeyPart{kind: 'c', value: typedParam.GetCacheKey()}
		default:
			return "", false
		}
		parts = append(parts, part)
		size += len(part.value) + decimalLen(len(part.value)) + 2
	}

	key := strings.Builder{}
	key.Grow(size)
	var lengthBuf [20]byte
	for _, part := range parts {
		key.WriteByte(part.kind)
		key.Write(strconv.AppendInt(lengthBuf[:0], int64(len(part.value)), 10))
		key.WriteByte(':')
		key.WriteString(part.value)
	}
	return key.String(), true
}

func decimalLen(n int) int {
	length := 1
	for ; n >= 10; n /= 10 {
		length++
	}
	return length
}

// ClearPolicy clears all policy.
func (e *CachedEnforcer) ClearPolicy() {
	e.barrier.Lock()
	defer e.barrier.Unlock()
	e.Enforcer.ClearPolicy()
	if err := e.invalidateCache(); err != nil {
		// Logger has been removed - error is ignored
		return
	}
}
