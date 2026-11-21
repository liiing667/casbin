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
	"container/list"
	"errors"
	"reflect"
	"sync"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// EnforcerFactory creates an enforcer for a cache entry. It is called only on
// a cache miss. The enforcer is shared by every caller that uses the same key,
// so it must be safe for concurrent use.
type EnforcerFactory func(key string, filter interface{}) (*SyncedEnforcer, error)

// EnforcerPool caches enforcers by tenant key and filter and bounds the cache
// with an LRU. It is intended for applications that would otherwise create a
// filtered enforcer for every request, for example one enforcer per tenant.
//
// A cached enforcer is returned only when both the key and the filter match
// the ones used to build it. Passing a different filter for the same key
// builds a new enforcer and replaces the previous entry, so a tenant switch
// can never return an enforcer that still holds another tenant's policy.
// Call Invalidate after a policy change that was not made through the cached
// enforcer, and call InvalidateAll from a watcher callback to drop enforcers
// built from a stale policy.
type EnforcerPool struct {
	mu        sync.Mutex
	factory   EnforcerFactory
	maxSize   int
	nextID    uint64
	enforcers map[uint64]*enforcerPoolEntry
	loading   map[uint64]*enforcerLoad
	lru       *list.List
}

type enforcerPoolEntry struct {
	id       uint64
	key      string
	filter   interface{}
	enforcer *SyncedEnforcer
	elem     *list.Element
}

type enforcerLoad struct {
	done     chan struct{}
	key      string
	filter   interface{}
	stale    bool
	enforcer *SyncedEnforcer
	err      error
}

var (
	errNilEnforcerFactory = errors.New("casbin: nil enforcer factory")
	errNilEnforcer        = errors.New("casbin: enforcer factory returned nil")
	errNilAdapterFactory  = errors.New("casbin: nil adapter factory")
)

// NewEnforcerPool creates a pool that keeps at most maxSize enforcers.
// A maxSize of zero or less means no limit.
func NewEnforcerPool(factory EnforcerFactory, maxSize int) *EnforcerPool {
	return &EnforcerPool{
		factory:   factory,
		maxSize:   maxSize,
		enforcers: make(map[uint64]*enforcerPoolEntry),
		loading:   make(map[uint64]*enforcerLoad),
		lru:       list.New(),
	}
}

// NewFilteredEnforcerPool creates a pool that builds one filtered enforcer per
// key. newAdapter is called once per enforcer, so adapters that keep filter
// state are not shared. The filter passed to Get must be the type the adapter
// expects.
func NewFilteredEnforcerPool(modelPath string, newAdapter func() persist.FilteredAdapter, maxSize int) *EnforcerPool {
	return NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		if newAdapter == nil {
			return nil, errNilAdapterFactory
		}

		m, err := model.NewModelFromFile(modelPath)
		if err != nil {
			return nil, err
		}

		e, err := NewSyncedEnforcer(m)
		if err != nil {
			return nil, err
		}

		e.SetAdapter(newAdapter())
		if err := e.LoadFilteredPolicy(filter); err != nil {
			return nil, err
		}

		return e, nil
	}, maxSize)
}

// Get returns the enforcer cached for key and filter. A cached enforcer is
// reused only when its filter is deeply equal to filter; otherwise the factory
// is called and the new enforcer replaces the entry that used the old filter.
// filter is passed to the factory unchanged. Concurrent calls with the same
// key and filter share one factory invocation.
func (p *EnforcerPool) Get(key string, filter interface{}) (*SyncedEnforcer, error) {
	if p.factory == nil {
		return nil, errNilEnforcerFactory
	}

	p.mu.Lock()
	p.initLocked()
	if entry := p.findEntryLocked(key, filter); entry != nil {
		p.lru.MoveToFront(entry.elem)
		e := entry.enforcer
		p.mu.Unlock()
		return e, nil
	}
	if load := p.findLoadLocked(key, filter); load != nil {
		p.mu.Unlock()
		return p.waitForLoad(key, filter, load)
	}

	load := &enforcerLoad{
		done:   make(chan struct{}),
		key:    key,
		filter: filter,
	}
	loadID := p.nextID
	p.nextID++
	p.loading[loadID] = load
	p.mu.Unlock()

	enforcer, err := p.factory(key, filter)
	if err == nil && enforcer == nil {
		err = errNilEnforcer
	}

	p.mu.Lock()
	delete(p.loading, loadID)
	load.enforcer = enforcer
	load.err = err
	close(load.done)
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}

	// The pool was invalidated while the factory was loading, so this
	// enforcer may have been built from a stale policy. Drop it and retry.
	if load.stale {
		p.mu.Unlock()
		return p.Get(key, filter)
	}

	// A concurrent retry may have inserted an entry for the exact same key
	// and filter while this goroutine was outside the lock. Keep one entry.
	if entry := p.findEntryLocked(key, filter); entry != nil {
		p.lru.MoveToFront(entry.elem)
		enforcer = entry.enforcer
		p.mu.Unlock()
		return enforcer, nil
	}

	// A different filter for the same key means a legitimate tenant switch:
	// drop the enforcer that held the old filter before inserting the new one
	// so the two tenants never share an instance.
	p.removeKeyLocked(key)

	entryID := p.nextID
	p.nextID++
	entry := &enforcerPoolEntry{
		id:       entryID,
		key:      key,
		filter:   filter,
		enforcer: enforcer,
	}
	entry.elem = p.lru.PushFront(entry)
	p.enforcers[entryID] = entry
	p.evictLocked()
	p.mu.Unlock()
	return enforcer, nil
}

func (p *EnforcerPool) waitForLoad(key string, filter interface{}, load *enforcerLoad) (*SyncedEnforcer, error) {
	<-load.done
	if load.err != nil {
		return nil, load.err
	}
	// The entry was invalidated while the factory was running. The loading
	// goroutine discards its result and retries, so resolve through the pool
	// again instead of handing back an enforcer that no longer belongs to it.
	if load.stale {
		return p.Get(key, filter)
	}
	return load.enforcer, nil
}

// Invalidate drops every enforcer cached for key, no matter which filter it
// was built with. Loads in progress for key are discarded when they finish.
func (p *EnforcerPool) Invalidate(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	p.removeKeyLocked(key)
	for _, load := range p.loading {
		if load.key == key {
			load.stale = true
		}
	}
}

// InvalidateAll drops every cached enforcer.
func (p *EnforcerPool) InvalidateAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	p.enforcers = make(map[uint64]*enforcerPoolEntry)
	p.lru.Init()
	for _, load := range p.loading {
		load.stale = true
	}
}

// OnUpdate invalidates every cached enforcer. Its signature matches the
// callback passed to persist.Watcher.SetUpdateCallback.
func (p *EnforcerPool) OnUpdate(string) {
	p.InvalidateAll()
}

// Len returns the number of cached enforcers.
func (p *EnforcerPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	return len(p.enforcers)
}

func (p *EnforcerPool) initLocked() {
	if p.enforcers == nil {
		p.enforcers = make(map[uint64]*enforcerPoolEntry)
	}
	if p.loading == nil {
		p.loading = make(map[uint64]*enforcerLoad)
	}
	if p.lru == nil {
		p.lru = list.New()
	}
}

// findEntryLocked returns the entry built with key and a deeply equal filter,
// or nil when no such entry is cached.
func (p *EnforcerPool) findEntryLocked(key string, filter interface{}) *enforcerPoolEntry {
	for _, entry := range p.enforcers {
		if entry.key == key && reflect.DeepEqual(entry.filter, filter) {
			return entry
		}
	}
	return nil
}

// findLoadLocked returns an in-flight load for key with a deeply equal filter.
func (p *EnforcerPool) findLoadLocked(key string, filter interface{}) *enforcerLoad {
	for _, load := range p.loading {
		if load.key == key && reflect.DeepEqual(load.filter, filter) {
			return load
		}
	}
	return nil
}

// removeKeyLocked drops every entry whose tenant key matches key, regardless
// of the filter the entry was built with.
func (p *EnforcerPool) removeKeyLocked(key string) {
	for id, entry := range p.enforcers {
		if entry.key == key {
			delete(p.enforcers, id)
			p.lru.Remove(entry.elem)
		}
	}
}

func (p *EnforcerPool) evictLocked() {
	if p.maxSize <= 0 {
		return
	}
	for len(p.enforcers) > p.maxSize {
		back := p.lru.Back()
		if back == nil {
			return
		}
		entry := back.Value.(*enforcerPoolEntry)
		delete(p.enforcers, entry.id)
		p.lru.Remove(back)
	}
}
