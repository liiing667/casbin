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
	"testing"
	"time"

	"github.com/casbin/casbin/v3/persist/cache"
	"github.com/casbin/casbin/v3/persist/string-adapter"
)

// enforceCached asserts the eventual decision of both cached enforcer flavors.
func enforceCached(t *testing.T, e interface {
	Enforce(...interface{}) (bool, error)
}, want bool, rvals ...interface{}) {
	t.Helper()
	got, err := e.Enforce(rvals...)
	if err != nil {
		t.Fatalf("Enforce(%v) error: %v", rvals, err)
	}
	if got != want {
		t.Errorf("Enforce(%v) = %t, want %t", rvals, got, want)
	}
}

// TestCachedRevokeDropsStaleAllow covers the revocation scenario: once a rule
// is removed, the old allow decision must never be served from the cache again.
func TestCachedRevokeDropsStaleAllow(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func() (interface {
			Enforce(...interface{}) (bool, error)
			RemovePolicy(...interface{}) (bool, error)
		}, error)
	}{
		{
			"cached enforcer",
			func() (interface {
				Enforce(...interface{}) (bool, error)
				RemovePolicy(...interface{}) (bool, error)
			}, error) {
				return NewCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
			},
		},
		{
			"synced cached enforcer",
			func() (interface {
				Enforce(...interface{}) (bool, error)
				RemovePolicy(...interface{}) (bool, error)
			}, error) {
				return NewSyncedCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := tc.new()
			if err != nil {
				t.Fatal(err)
			}
			enforceCached(t, e, true, "alice", "data1", "read")

			if _, err := e.RemovePolicy("alice", "data1", "read"); err != nil {
				t.Fatal(err)
			}

			// Repeated reads must all observe the new generation's decision.
			for i := 0; i < 10; i++ {
				enforceCached(t, e, false, "alice", "data1", "read")
			}
		})
	}
}

// TestCachedAddPolicyStillWorks covers the ordinary add scenario, which must
// keep behaving exactly as without the cache.
func TestCachedAddPolicyStillWorks(t *testing.T) {
	e, err := NewCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	enforceCached(t, e, false, "bob", "data1", "read")

	if _, err := e.AddPolicy("bob", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	enforceCached(t, e, true, "bob", "data1", "read")

	// Adding a rule that does not affect this key leaves its decision intact.
	if _, err := e.AddPolicy("bob", "data2", "write"); err != nil {
		t.Fatal(err)
	}
	enforceCached(t, e, true, "bob", "data1", "read")
	enforceCached(t, e, true, "bob", "data2", "write")
}

// reloadWatcher invokes its update callback, imitating a watcher telling the
// enforcer that another node changed the shared policy.
type reloadWatcher struct {
	callback func(string)
}

func (w *reloadWatcher) Close() {}

func (w *reloadWatcher) SetUpdateCallback(callback func(string)) error {
	w.callback = callback
	return nil
}

func (w *reloadWatcher) Update() error {
	if w.callback != nil {
		w.callback("")
	}
	return nil
}

// TestCachedWatcherReloadUsesSingleGeneration covers the watcher scenario: a
// reload triggered through the watcher callback must not mix decisions from
// the old and new policy generations.
func TestCachedWatcherReloadUsesSingleGeneration(t *testing.T) {
	adapter := stringadapter.NewAdapter("p, alice, data1, read\n")
	e, err := NewCachedEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	watcher := &reloadWatcher{}
	if err := e.SetWatcher(watcher); err != nil {
		t.Fatal(err)
	}
	if err := e.watcher.SetUpdateCallback(func(string) {
		if err := e.LoadPolicy(); err != nil {
			t.Errorf("LoadPolicy in watcher callback: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}

	// Prime the cache with the original policy.
	enforceCached(t, e, true, "alice", "data1", "read")

	// Rewrite the underlying policy so the rule no longer exists, then notify.
	adapter.Line = "p, bob, data1, read\n"
	_ = watcher.Update()

	// After the watcher reload, every read must come from the current
	// generation: alice lost the rule while bob gained it.
	enforceCached(t, e, false, "alice", "data1", "read")
	enforceCached(t, e, true, "bob", "data1", "read")
	for i := 0; i < 10; i++ {
		enforceCached(t, e, false, "alice", "data1", "read")
	}
}

// TestCachedConcurrentReadAfterRevoke covers the concurrent-read scenario:
// reads racing with a revocation must only ever return the post-revoke result
// once the revocation has completed.
func TestCachedConcurrentReadAfterRevoke(t *testing.T) {
	for _, tc := range []struct {
		name string
		new  func() (interface {
			Enforce(...interface{}) (bool, error)
			RemovePolicy(...interface{}) (bool, error)
		}, error)
	}{
		{
			"cached enforcer",
			func() (interface {
				Enforce(...interface{}) (bool, error)
				RemovePolicy(...interface{}) (bool, error)
			}, error) {
				return NewCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
			},
		},
		{
			"synced cached enforcer",
			func() (interface {
				Enforce(...interface{}) (bool, error)
				RemovePolicy(...interface{}) (bool, error)
			}, error) {
				return NewSyncedCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for iter := 0; iter < 50; iter++ {
				e, err := tc.new()
				if err != nil {
					t.Fatal(err)
				}
				enforceCached(t, e, true, "alice", "data1", "read")

				var removed int32
				var stale int32
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _ = e.RemovePolicy("alice", "data1", "read")
					atomic.StoreInt32(&removed, 1)
				}()
				go func() {
					defer wg.Done()
					for i := 0; i < 1000; i++ {
						ok, _ := e.Enforce("alice", "data1", "read")
						if ok && atomic.LoadInt32(&removed) == 1 {
							atomic.StoreInt32(&stale, 1)
							return
						}
					}
				}()
				wg.Wait()

				if atomic.LoadInt32(&stale) == 1 {
					t.Fatalf("iter %d: stale allow after revoke completed", iter)
				}
				enforceCached(t, e, false, "alice", "data1", "read")
			}
		})
	}
}

// TestCachedExpireRefreshesInCurrentGeneration covers the expiry scenario: an
// expired entry is recomputed against the current generation and a decision
// cached after expiry must match the live policy.
func TestCachedExpireRefreshesInCurrentGeneration(t *testing.T) {
	e, err := NewCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	e.SetExpireTime(20 * time.Millisecond)

	enforceCached(t, e, true, "alice", "data1", "read")
	// Within the TTL the cached decision is served.
	time.Sleep(5 * time.Millisecond)
	enforceCached(t, e, true, "alice", "data1", "read")

	// After expiry the entry is recomputed and re-cached.
	time.Sleep(25 * time.Millisecond)
	enforceCached(t, e, true, "alice", "data1", "read")

	if _, err := e.RemovePolicy("alice", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	// Expiry and revocation together still yield the current generation.
	time.Sleep(25 * time.Millisecond)
	enforceCached(t, e, false, "alice", "data1", "read")
}

// TestCachedGenerationRejectsMixedBackingEntries verifies the generation guard
// itself: an entry left in the backing cache without a matching tag is treated
// as a miss rather than served across generations.
func TestCachedGenerationRejectsMixedBackingEntries(t *testing.T) {
	e, err := NewCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	enforceCached(t, e, true, "alice", "data1", "read")

	key, ok := e.getKey("alice", "data1", "read")
	if !ok {
		t.Fatal("cache key should be buildable")
	}
	oldGeneration := e.cache.currentGeneration()

	// Advance the generation but leave a stale value in the backing cache,
	// simulating a backend that does not synchronously drop entries.
	if err := e.cache.cache.Set(key, true); err != nil {
		t.Fatal(err)
	}
	if err := e.cache.clear(); err != nil {
		t.Fatal(err)
	}
	if e.cache.currentGeneration() == oldGeneration {
		t.Fatal("generation must advance on clear")
	}
	// The untagged backing entry must not be served.
	if _, err := e.cache.getForGeneration(e.cache.currentGeneration(), key); err != cache.ErrNoSuchKey {
		t.Fatalf("stale backing entry served across generations, err=%v", err)
	}
}
