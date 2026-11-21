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
	"context"
	"errors"
	"testing"

	"github.com/casbin/casbin/v3/model"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

// faultFilteredAdapter is an in-memory FilteredAdapter used to reproduce a
// multi-tenant switch whose upstream fails in the middle of the load. It adds a
// handful of rules to the staging model and then returns an error, so any
// non-atomic implementation would expose those rules through the live model.
type faultFilteredAdapter struct {
	// tenants maps a domain to the rules that a successful filtered load returns.
	tenants map[string][][]string
	// groupings maps a domain to its role inheritance rules.
	groupings map[string][][]string
	// failAfter is the number of rules that are added before the injected error
	// is returned. A negative value disables the fault.
	failAfter int
	failErr   error

	filtered bool
	// calls counts the filtered loads so a failing tenant can be retried with the
	// fault switched off.
	calls int
}

func newFaultFilteredAdapter() *faultFilteredAdapter {
	return &faultFilteredAdapter{
		tenants: map[string][][]string{
			"domain1": {
				{"admin", "domain1", "data1", "read"},
				{"admin", "domain1", "data1", "write"},
			},
			"domain2": {
				{"admin", "domain2", "data2", "read"},
				{"admin", "domain2", "data2", "write"},
			},
		},
		groupings: map[string][][]string{
			"domain1": {{"alice", "admin", "domain1"}},
			"domain2": {{"bob", "admin", "domain2"}},
		},
		failAfter: -1,
	}
}

func (a *faultFilteredAdapter) domain(filter interface{}) string {
	f, ok := filter.(*fileadapter.Filter)
	if !ok || len(f.P) < 2 {
		return ""
	}
	return f.P[1]
}

func (a *faultFilteredAdapter) load(m model.Model, filter interface{}, failAfter int) error {
	a.calls++
	rules := a.tenants[a.domain(filter)]
	for i, rule := range rules {
		if i == failAfter {
			a.filtered = false
			return a.failErr
		}
		if err := m.AddPolicy("p", "p", rule); err != nil {
			return err
		}
	}
	for _, rule := range a.groupings[a.domain(filter)] {
		if err := m.AddPolicy("g", "g", rule); err != nil {
			return err
		}
	}
	a.filtered = true
	return nil
}

func (a *faultFilteredAdapter) LoadPolicy(m model.Model) error {
	a.filtered = false
	for _, rules := range a.tenants {
		for _, rule := range rules {
			if err := m.AddPolicy("p", "p", rule); err != nil {
				return err
			}
		}
	}
	for _, rules := range a.groupings {
		for _, rule := range rules {
			if err := m.AddPolicy("g", "g", rule); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *faultFilteredAdapter) SavePolicy(model.Model) error { return nil }

func (a *faultFilteredAdapter) AddPolicy(string, string, []string) error { return nil }
func (a *faultFilteredAdapter) RemovePolicy(string, string, []string) error {
	return nil
}
func (a *faultFilteredAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return nil
}

func (a *faultFilteredAdapter) LoadFilteredPolicy(m model.Model, filter interface{}) error {
	return a.load(m, filter, a.failAfter)
}

func (a *faultFilteredAdapter) IsFiltered() bool { return a.filtered }

// The context-aware variant honours cancellation before the fault point.
func (a *faultFilteredAdapter) LoadPolicyCtx(_ context.Context, m model.Model) error {
	return a.LoadPolicy(m)
}

func (a *faultFilteredAdapter) SavePolicyCtx(context.Context, model.Model) error { return nil }
func (a *faultFilteredAdapter) AddPolicyCtx(context.Context, string, string, []string) error {
	return nil
}
func (a *faultFilteredAdapter) RemovePolicyCtx(context.Context, string, string, []string) error {
	return nil
}
func (a *faultFilteredAdapter) RemoveFilteredPolicyCtx(context.Context, string, string, int, ...string) error {
	return nil
}

func (a *faultFilteredAdapter) LoadFilteredPolicyCtx(ctx context.Context, m model.Model, filter interface{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.load(m, filter, a.failAfter)
}

func (a *faultFilteredAdapter) IsFilteredCtx(context.Context) bool { return a.filtered }

// newFaultEnforcer builds an enforcer whose initial view is the full policy of
// domain1, matching a process that already serves a tenant.
func newFaultEnforcer(t *testing.T, adapter *faultFilteredAdapter) *Enforcer {
	t.Helper()
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}
	if err := e.InitWithAdapter("examples/rbac_with_domains_model.conf", adapter); err != nil {
		t.Fatalf("InitWithAdapter failed: %v", err)
	}
	if err := e.LoadFilteredPolicy(&fileadapter.Filter{P: []string{"", "domain1"}}); err != nil {
		t.Fatalf("initial LoadFilteredPolicy failed: %v", err)
	}
	return e
}

// TestFilteredPolicySwitchKeepsTenantViewOnFailure verifies that a failed
// tenant switch never exposes a half-populated view: every rule of the previous
// tenant stays visible and none of the new tenant leaks in.
func TestFilteredPolicySwitchKeepsTenantViewOnFailure(t *testing.T) {
	adapter := newFaultFilteredAdapter()
	e := newFaultEnforcer(t, adapter)

	adapter.failAfter = 1
	adapter.failErr = errors.New("upstream storage unavailable")
	err := e.LoadFilteredPolicy(&fileadapter.Filter{P: []string{"", "domain2"}})
	if err == nil {
		t.Fatal("expected the failing adapter to surface an error")
	}

	// The previous tenant view must be fully intact.
	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "write"}, true)
	// The single rule the adapter added before failing must never be visible.
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "read"}, false)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "write"}, false)

	// Enforcement decisions still follow the old, complete view.
	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain2", "data2", "read", false)

	// Once the upstream recovers, the switch completes atomically.
	adapter.failAfter = -1
	if err := e.LoadFilteredPolicy(&fileadapter.Filter{P: []string{"", "domain2"}}); err != nil {
		t.Fatalf("retry LoadFilteredPolicy failed: %v", err)
	}
	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "read"}, false)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "write"}, true)
}

// TestIncrementalFilteredPolicyKeepsBaseViewOnFailure verifies that an
// incremental (append) filtered load preserves both the existing view and its
// all-or-nothing semantics when the adapter fails midway.
func TestIncrementalFilteredPolicyKeepsBaseViewOnFailure(t *testing.T) {
	adapter := newFaultFilteredAdapter()
	e := newFaultEnforcer(t, adapter)

	adapter.failErr = errors.New("upstream storage unavailable")
	adapter.failAfter = 1
	err := e.LoadIncrementalFilteredPolicy(&fileadapter.Filter{P: []string{"", "domain2"}})
	if err == nil {
		t.Fatal("expected the failing adapter to surface an error")
	}

	// Base tenant rules remain and none of the partial append is visible.
	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "write"}, true)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "read"}, false)

	// A successful incremental load appends the second tenant without dropping
	// the first one.
	adapter.failAfter = -1
	if err := e.LoadIncrementalFilteredPolicy(&fileadapter.Filter{P: []string{"", "domain2"}}); err != nil {
		t.Fatalf("retry LoadIncrementalFilteredPolicy failed: %v", err)
	}
	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "write"}, true)
}

// TestFilteredPolicyCancelKeepsTenantView verifies that a cancelled context
// aborts the switch and leaves the previous tenant view untouched.
func TestFilteredPolicyCancelKeepsTenantView(t *testing.T) {
	adapter := newFaultFilteredAdapter()
	e := newFaultEnforcer(t, adapter)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.LoadFilteredPolicyCtx(ctx, &fileadapter.Filter{P: []string{"", "domain2"}}); err == nil {
		t.Fatal("expected the cancelled context to abort the load")
	}

	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "read"}, false)
}

// TestFilteredPolicyValidSwitch verifies the happy path: a legal filter swaps
// the complete view of one tenant for another.
func TestFilteredPolicyValidSwitch(t *testing.T) {
	adapter := newFaultFilteredAdapter()
	e := newFaultEnforcer(t, adapter)

	if err := e.LoadFilteredPolicy(&fileadapter.Filter{P: []string{"", "domain2"}}); err != nil {
		t.Fatalf("LoadFilteredPolicy failed: %v", err)
	}
	if !e.IsFiltered() {
		t.Fatal("adapter did not set the filtered flag")
	}
	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "read"}, false)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "write"}, true)
}

// TestPlainLoadPolicyStillSucceeds verifies the ordinary, non-filtered load
// path is unaffected by the atomicity rework.
func TestPlainLoadPolicyStillSucceeds(t *testing.T) {
	adapter := newFaultFilteredAdapter()
	e, err := NewEnforcer()
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}
	if err := e.InitWithAdapter("examples/rbac_with_domains_model.conf", adapter); err != nil {
		t.Fatalf("InitWithAdapter failed: %v", err)
	}

	testHasPolicy(t, e, []string{"admin", "domain1", "data1", "read"}, true)
	testHasPolicy(t, e, []string{"admin", "domain2", "data2", "write"}, true)
	if e.IsFiltered() {
		t.Fatal("plain LoadPolicy must not mark the enforcer as filtered")
	}
}
