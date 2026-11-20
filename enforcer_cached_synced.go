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
	"time"

	"github.com/casbin/casbin/v3/persist/cache"
)

// SyncedCachedEnforcer wraps Enforcer and provides decision sync cache.
type SyncedCachedEnforcer struct {
	*SyncedEnforcer
	expireTime  time.Duration
	cache       *generationCache
	enableCache int32
	// locker guards expireTime and cache replacement.
	locker sync.RWMutex
}

// NewSyncedCachedEnforcer creates a sync cached enforcer via file or DB.
func NewSyncedCachedEnforcer(params ...interface{}) (*SyncedCachedEnforcer, error) {
	e := &SyncedCachedEnforcer{}
	var err error
	e.SyncedEnforcer, err = NewSyncedEnforcer(params...)
	if err != nil {
		return nil, err
	}

	e.enableCache = 1
	innerCache, _ := cache.NewConcurrentCache(cache.DefaultConcurrentCacheSize)
	e.cache = newGenerationCache(innerCache)
	return e, nil
}

// EnableCache determines whether to enable cache on Enforce(). When enableCache is enabled, cached result (true | false) will be returned for previous decisions.
func (e *SyncedCachedEnforcer) EnableCache(enableCache bool) {
	var enabled int32
	if enableCache {
		enabled = 1
	}
	atomic.StoreInt32(&e.enableCache, enabled)
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
// if rvals is not string , ignore the cache.
func (e *SyncedCachedEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	if atomic.LoadInt32(&e.enableCache) == 0 || !e.enabled {
		return e.SyncedEnforcer.Enforce(rvals...)
	}

	key, ok := e.getKey(rvals...)
	if !ok {
		return e.SyncedEnforcer.Enforce(rvals...)
	}

	// The read lock spans the whole decision, so a mutation cannot advance the
	// cache generation mid-flight. Enforcer.Enforce does not take e.m, avoiding
	// a re-entrant read lock.
	e.m.RLock()
	defer e.m.RUnlock()

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
	if err := e.cache.set(snapshot, key, res, e.expireTime); err != nil {
		return res, err
	}
	return res, nil
}

// invalidateCacheIfEnabled advances the cache generation. The caller must hold
// the write lock so the invalidation is atomic relative to Enforce.
func (e *SyncedCachedEnforcer) invalidateCacheIfEnabled() error {
	if atomic.LoadInt32(&e.enableCache) == 0 {
		return nil
	}
	return e.cache.clear()
}

// mutate runs a policy or role-link change and, after it has finished, advances
// the cache generation so every decision from the previous state is discarded.
func (e *SyncedCachedEnforcer) mutate(fn func() (bool, error)) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	affected, err := fn()
	if err != nil {
		return affected, err
	}
	if err := e.invalidateCacheIfEnabled(); err != nil {
		return affected, err
	}
	return affected, nil
}

func (e *SyncedCachedEnforcer) LoadPolicy() error {
	e.m.Lock()
	defer e.m.Unlock()
	if err := e.Enforcer.LoadPolicy(); err != nil {
		return err
	}
	return e.invalidateCacheIfEnabled()
}

func (e *SyncedCachedEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.AddPolicy(params...)
	})
}

func (e *SyncedCachedEnforcer) AddPolicies(rules [][]string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.AddPolicies(rules)
	})
}

func (e *SyncedCachedEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemovePolicy(params...)
	})
}

func (e *SyncedCachedEnforcer) RemovePolicies(rules [][]string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemovePolicies(rules)
	})
}

func (e *SyncedCachedEnforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
	})
}

func (e *SyncedCachedEnforcer) UpdatePolicy(oldPolicy []string, newPolicy []string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.UpdatePolicy(oldPolicy, newPolicy)
	})
}

func (e *SyncedCachedEnforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.AddGroupingPolicy(params...)
	})
}

func (e *SyncedCachedEnforcer) RemoveGroupingPolicy(params ...interface{}) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemoveGroupingPolicy(params...)
	})
}

func (e *SyncedCachedEnforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	return e.mutate(func() (bool, error) {
		return e.Enforcer.RemoveFilteredGroupingPolicy(fieldIndex, fieldValues...)
	})
}

func (e *SyncedCachedEnforcer) SetExpireTime(expireTime time.Duration) {
	e.locker.Lock()
	defer e.locker.Unlock()
	e.expireTime = expireTime
}

// SetCache need to be sync cache.
func (e *SyncedCachedEnforcer) SetCache(c cache.Cache) {
	e.locker.Lock()
	defer e.locker.Unlock()
	e.cache = newGenerationCache(c).withGeneration(e.cache.currentGeneration())
}

func (e *SyncedCachedEnforcer) getKey(params ...interface{}) (string, bool) {
	return GetCacheKey(params...)
}

// InvalidateCache deletes all the existing cached decisions.
func (e *SyncedCachedEnforcer) InvalidateCache() error {
	return e.cache.clear()
}
