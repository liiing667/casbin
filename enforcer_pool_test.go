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
	"errors"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v3/persist"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

func newTestPoolEnforcer() (*SyncedEnforcer, error) {
	return NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
}

func TestEnforcerPoolGetCaches(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	e1, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	e2, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if calls != 1 {
		t.Fatalf("factory calls = %d, want 1", calls)
	}
	if e1 != e2 {
		t.Fatal("Get returned different enforcers for the same key")
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
}

func TestEnforcerPoolDifferentKeys(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	e1, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	e2, err := pool.Get("tenant2", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if calls != 2 {
		t.Fatalf("factory calls = %d, want 2", calls)
	}
	if e1 == e2 {
		t.Fatal("Get returned the same enforcer for different keys")
	}
	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pool.Len())
	}
}

func TestEnforcerPoolInvalidate(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	e1, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	pool.Invalidate("tenant1")
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0", pool.Len())
	}

	e2, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if calls != 2 {
		t.Fatalf("factory calls = %d, want 2", calls)
	}
	if e1 == e2 {
		t.Fatal("Get returned the invalidated enforcer")
	}

	pool.Invalidate("missing")
}

func TestEnforcerPoolInvalidateAll(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	if _, err := pool.Get("tenant1", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := pool.Get("tenant2", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}

	pool.OnUpdate("policy changed")
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0", pool.Len())
	}

	if _, err := pool.Get("tenant1", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if calls != 3 {
		t.Fatalf("factory calls = %d, want 3", calls)
	}
}

func TestEnforcerPoolLRU(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 2)

	get := func(key string) *SyncedEnforcer {
		e, err := pool.Get(key, nil)
		if err != nil {
			t.Fatalf("Get(%q): %v", key, err)
		}
		return e
	}

	get("a")
	get("b")
	get("a")
	get("c")
	get("b")
	get("c")

	if calls != 4 {
		t.Fatalf("factory calls = %d, want 4", calls)
	}
	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pool.Len())
	}
}

func TestEnforcerPoolUnbounded(t *testing.T) {
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		return newTestPoolEnforcer()
	}, 0)

	for i := 0; i < 50; i++ {
		if _, err := pool.Get(strconv.Itoa(i), nil); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if pool.Len() != 50 {
		t.Fatalf("Len = %d, want 50", pool.Len())
	}
}

func TestEnforcerPoolFactoryError(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return nil, boom
	}, 10)

	if _, err := pool.Get("tenant1", nil); !errors.Is(err, boom) {
		t.Fatalf("Get error = %v, want %v", err, boom)
	}
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0", pool.Len())
	}

	if _, err := pool.Get("tenant1", nil); !errors.Is(err, boom) {
		t.Fatalf("Get error = %v, want %v", err, boom)
	}
	if calls != 2 {
		t.Fatalf("factory calls = %d, want 2", calls)
	}
}

func TestEnforcerPoolNilFactory(t *testing.T) {
	pool := NewEnforcerPool(nil, 10)
	if _, err := pool.Get("tenant1", nil); err != errNilEnforcerFactory {
		t.Fatalf("Get error = %v, want %v", err, errNilEnforcerFactory)
	}
}

func TestEnforcerPoolNilEnforcer(t *testing.T) {
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		return nil, nil
	}, 10)
	if _, err := pool.Get("tenant1", nil); err != errNilEnforcer {
		t.Fatalf("Get error = %v, want %v", err, errNilEnforcer)
	}
}

func TestEnforcerPoolConcurrentGet(t *testing.T) {
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		return newTestPoolEnforcer()
	}, 10)

	const n = 100
	results := make([]*SyncedEnforcer, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			e, err := pool.Get("tenant1", nil)
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			results[i] = e
		}(i)
	}
	wg.Wait()

	if t.Failed() {
		return
	}
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("Get returned different enforcers for the same key")
		}
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
}

func TestEnforcerPoolInvalidateDuringLoad(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
			<-release
		}
		return newTestPoolEnforcer()
	}, 10)

	go func() {
		<-started
		pool.InvalidateAll()
		close(release)
	}()

	if _, err := pool.Get("tenant1", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("factory calls = %d, want 2", got)
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
}

func TestNewFilteredEnforcerPool(t *testing.T) {
	pool := NewFilteredEnforcerPool(
		"examples/rbac_with_domains_model.conf",
		func() persist.FilteredAdapter {
			return fileadapter.NewFilteredAdapter("examples/rbac_with_domains_policy.csv")
		},
		10,
	)

	e, err := pool.Get("domain1", &fileadapter.Filter{P: []string{"", "domain1"}})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	policy, err := e.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(policy) != 2 {
		t.Fatalf("policy length = %d, want 2", len(policy))
	}

	allowed, err := e.Enforce("admin", "domain1", "data1", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Fatal("domain1 policy was not loaded")
	}

	allowed, err = e.Enforce("admin", "domain2", "data2", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if allowed {
		t.Fatal("domain2 policy was loaded by the domain1 enforcer")
	}
}

// TestEnforcerPoolSimilarKeys makes sure keys that share a prefix or differ
// only by separators never resolve to the same pooled instance.
func TestEnforcerPoolSimilarKeys(t *testing.T) {
	created := make(map[string]*SyncedEnforcer)
	var mu sync.Mutex
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		e, err := newTestPoolEnforcer()
		if err != nil {
			return nil, err
		}
		mu.Lock()
		created[key] = e
		mu.Unlock()
		return e, nil
	}, 10)

	keys := []string{"tenant", "tenant1", "tenant/1", "tenant:1", "1tenant", " tenant1", "tenant1 "}
	got := make(map[string]*SyncedEnforcer, len(keys))
	for _, key := range keys {
		e, err := pool.Get(key, nil)
		if err != nil {
			t.Fatalf("Get(%q): %v", key, err)
		}
		got[key] = e
	}

	if pool.Len() != len(keys) {
		t.Fatalf("Len = %d, want %d", pool.Len(), len(keys))
	}
	seen := make(map[*SyncedEnforcer]string)
	for key, e := range got {
		if other, ok := seen[e]; ok {
			t.Fatalf("keys %q and %q share the same enforcer", key, other)
		}
		seen[e] = key
		if created[key] != e {
			t.Fatalf("Get(%q) returned an enforcer built for another key", key)
		}
	}
}

// TestEnforcerPoolFilterSwitchIsolation verifies that passing a different
// filter for the same key never returns the enforcer built for the old
// filter, and that the old enforcer keeps its own policy afterwards.
func TestEnforcerPoolFilterSwitchIsolation(t *testing.T) {
	newAdapter := func() persist.FilteredAdapter {
		return fileadapter.NewFilteredAdapter("examples/rbac_with_domains_policy.csv")
	}
	pool := NewFilteredEnforcerPool("examples/rbac_with_domains_model.conf", newAdapter, 10)

	filter1 := &fileadapter.Filter{P: []string{"", "domain1"}}
	filter1Equal := &fileadapter.Filter{P: []string{"", "domain1"}}
	filter2 := &fileadapter.Filter{P: []string{"", "domain2"}}

	first, err := pool.Get("tenant", filter1)
	if err != nil {
		t.Fatalf("Get filter1: %v", err)
	}

	// A distinct but deeply equal filter value must reuse the same instance.
	again, err := pool.Get("tenant", filter1Equal)
	if err != nil {
		t.Fatalf("Get equal filter: %v", err)
	}
	if again != first {
		t.Fatal("equal filters did not reuse the same enforcer")
	}

	// Switching the filter for the same key builds an isolated replacement.
	second, err := pool.Get("tenant", filter2)
	if err != nil {
		t.Fatalf("Get filter2: %v", err)
	}
	if second == first {
		t.Fatal("filter switch returned the previous tenant's enforcer")
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1 after a filter switch", pool.Len())
	}

	if allowed, err := second.Enforce("admin", "domain2", "data2", "read"); err != nil || !allowed {
		t.Fatalf("new enforcer does not hold the domain2 policy: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := second.Enforce("admin", "domain1", "data1", "read"); err != nil || allowed {
		t.Fatalf("new enforcer leaked the domain1 policy: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := first.Enforce("admin", "domain1", "data1", "read"); err != nil || !allowed {
		t.Fatalf("old enforcer lost its domain1 policy: allowed=%v err=%v", allowed, err)
	}

	// Going back to the first filter must not hand back the domain2 instance.
	back, err := pool.Get("tenant", filter1)
	if err != nil {
		t.Fatalf("Get filter1 again: %v", err)
	}
	if back == second {
		t.Fatal("switching back returned the domain2 enforcer")
	}
	if allowed, err := back.Enforce("admin", "domain1", "data1", "read"); err != nil || !allowed {
		t.Fatalf("rebuilt enforcer does not hold the domain1 policy: allowed=%v err=%v", allowed, err)
	}
}

// TestEnforcerPoolDifferentFiltersDifferentTenants checks that two tenants
// whose keys differ only in the filter always receive separate enforcers.
func TestEnforcerPoolDifferentFiltersDifferentTenants(t *testing.T) {
	newAdapter := func() persist.FilteredAdapter {
		return fileadapter.NewFilteredAdapter("examples/rbac_with_domains_policy.csv")
	}
	pool := NewFilteredEnforcerPool("examples/rbac_with_domains_model.conf", newAdapter, 10)

	e1, err := pool.Get("shared", &fileadapter.Filter{P: []string{"", "domain1"}})
	if err != nil {
		t.Fatalf("Get domain1: %v", err)
	}
	e2, err := pool.Get("shared", &fileadapter.Filter{P: []string{"", "domain2"}})
	if err != nil {
		t.Fatalf("Get domain2: %v", err)
	}
	if e1 == e2 {
		t.Fatal("different filters for the same key returned the same enforcer")
	}

	allowed, err := e1.Enforce("admin", "domain1", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("domain1 enforcer wrong: allowed=%v err=%v", allowed, err)
	}
	allowed, err = e1.Enforce("admin", "domain2", "data2", "read")
	if err != nil || allowed {
		t.Fatalf("domain1 enforcer holds domain2 policy: allowed=%v err=%v", allowed, err)
	}
}

// TestEnforcerPoolConcurrentLoadDedup ensures concurrent Gets for one
// key/filter pair trigger a single factory call and all callers get the same
// instance, while a different filter loads independently.
func TestEnforcerPoolConcurrentLoadDedup(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
			<-release
		}
		return newTestPoolEnforcer()
	}, 10)

	const waiters = 50
	var wg sync.WaitGroup
	results := make([]*SyncedEnforcer, waiters)
	wg.Add(waiters)
	for i := 0; i < waiters; i++ {
		go func(i int) {
			defer wg.Done()
			e, err := pool.Get("tenant1", nil)
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			results[i] = e
		}(i)
	}

	<-started
	other, err := pool.Get("tenant2", nil)
	if err != nil {
		t.Fatalf("Get tenant2: %v", err)
	}
	close(release)
	wg.Wait()

	if t.Failed() {
		return
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("factory calls = %d, want 2", got)
	}
	for i := range results {
		if results[i] != results[0] {
			t.Fatal("waiters received different enforcers for the same key/filter")
		}
		if results[i] == other {
			t.Fatal("tenant2 received the enforcer loaded for tenant1")
		}
	}
	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pool.Len())
	}
}

// TestEnforcerPoolConcurrentEvictionIsolation hammers a bounded pool from
// multiple goroutines and checks that an evicted tenant can never observe
// another tenant's enforcer on its next Get.
func TestEnforcerPoolConcurrentEvictionIsolation(t *testing.T) {
	const tenants = 20
	const maxSize = 4
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		return newTestPoolEnforcer()
	}, maxSize)

	var wg sync.WaitGroup
	for round := 0; round < 8; round++ {
		for i := 0; i < tenants; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				key := "tenant-" + strconv.Itoa(i)
				filter := &fileadapter.Filter{P: []string{"", key}}
				e, err := pool.Get(key, filter)
				if err != nil {
					t.Errorf("Get: %v", err)
					return
				}
				if e == nil {
					t.Error("Get returned a nil enforcer")
				}
				if pool.Len() > maxSize {
					t.Errorf("Len = %d, exceeds maxSize %d", pool.Len(), maxSize)
				}
			}(i)
		}
	}
	wg.Wait()

	if pool.Len() > maxSize {
		t.Fatalf("Len = %d, exceeds maxSize %d", pool.Len(), maxSize)
	}

	for i := 0; i < tenants; i++ {
		key := "tenant-" + strconv.Itoa(i)
		filter := &fileadapter.Filter{P: []string{"", key}}
		e, err := pool.Get(key, filter)
		if err != nil {
			t.Fatalf("Get %q: %v", key, err)
		}
		again, err := pool.Get(key, filter)
		if err != nil {
			t.Fatalf("Get %q again: %v", key, err)
		}
		if e != again {
			t.Fatalf("tenant %q did not get a stable instance within the pool", key)
		}
	}
}

// TestEnforcerPoolInvalidateDuringFilteredLoad ensures an invalidation while a
// filtered enforcer is loading causes a reload rather than caching an enforcer
// built from potentially stale data.
func TestEnforcerPoolInvalidateDuringFilteredLoad(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
			<-release
		}
		return newTestPoolEnforcer()
	}, 10)

	filter := &fileadapter.Filter{P: []string{"", "domain1"}}
	go func() {
		<-started
		pool.Invalidate("tenant1")
		close(release)
	}()

	if _, err := pool.Get("tenant1", filter); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("factory calls = %d, want 2", got)
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
}

// TestEnforcerPoolWaiterAfterInvalidate ensures goroutines waiting on an
// in-flight load do not keep an instance that an invalidation just dropped.
func TestEnforcerPoolWaiterAfterInvalidate(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	waiterJoined := make(chan struct{})
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		atomic.AddInt32(&calls, 1)
		if atomic.LoadInt32(&calls) == 1 {
			close(started)
			<-release
		}
		return newTestPoolEnforcer()
	}, 10)

	filter := &fileadapter.Filter{P: []string{"", "domain1"}}
	type result struct {
		e   *SyncedEnforcer
		err error
	}
	results := make(chan result, 2)
	go func() {
		e, err := pool.Get("tenant1", filter)
		results <- result{e, err}
	}()

	<-started
	go func() {
		pool.mu.Lock()
		for len(pool.loading) == 0 {
			pool.mu.Unlock()
			runtime.Gosched()
			pool.mu.Lock()
		}
		pool.mu.Unlock()
		close(waiterJoined)
		e, err := pool.Get("tenant1", filter)
		results <- result{e, err}
	}()

	<-waiterJoined
	pool.Invalidate("tenant1")
	close(release)

	first := <-results
	second := <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("Get returned errors: %v %v", first.err, second.err)
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}

	current, err := pool.Get("tenant1", filter)
	if err != nil {
		t.Fatalf("Get after invalidate: %v", err)
	}
	for _, r := range []result{first, second} {
		if r.e != current {
			t.Fatal("a caller kept an enforcer that was invalidated")
		}
	}
}
