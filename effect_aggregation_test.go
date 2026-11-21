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
	"testing"

	"github.com/casbin/casbin/v3/model"
)

const (
	testAllowOverride = "some(where (p.eft == allow))"
	testDenyOverride  = "!some(where (p.eft == deny))"
	testAllowAndDeny  = "some(where (p.eft == allow)) && !some(where (p.eft == deny))"
	testPriority      = "priority(p.eft) || deny"
)

func newEffectTestEnforcer(t *testing.T, effect string, rules [][]string) *Enforcer {
	t.Helper()
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act, eft")
	m.AddDef("e", "e", effect)
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	for _, rule := range rules {
		if _, err := e.AddPolicy(rule); err != nil {
			t.Fatalf("AddPolicy %v: %v", rule, err)
		}
	}
	return e
}

func newExplicitPriorityEnforcer(t *testing.T, rules [][]string) *Enforcer {
	t.Helper()
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "priority, sub, obj, act, eft")
	m.AddDef("e", "e", testPriority)
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatalf("AddPolicies: %v", err)
	}
	// LoadPolicy sorts by priority; AddPolicies does not, so sort explicitly.
	if err := e.model.SortPoliciesByPriority(); err != nil {
		t.Fatalf("SortPoliciesByPriority: %v", err)
	}
	return e
}

func TestEffectAggregationAllowOverride(t *testing.T) {
	e := newEffectTestEnforcer(t, testAllowOverride, [][]string{
		{"alice", "data1", "read", "deny"},
		{"alice", "data1", "read", "allow"},
	})
	testEnforce(t, e, "alice", "data1", "read", true)

	// Deny-only and unmatched requests stay denied.
	e = newEffectTestEnforcer(t, testAllowOverride, [][]string{
		{"alice", "data1", "read", "deny"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "read", false)
}

func TestEffectAggregationDenyOverride(t *testing.T) {
	e := newEffectTestEnforcer(t, testDenyOverride, [][]string{
		{"alice", "data1", "read", "allow"},
		{"alice", "data1", "read", "deny"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)

	e = newEffectTestEnforcer(t, testDenyOverride, [][]string{
		{"alice", "data1", "read", "allow"},
	})
	testEnforce(t, e, "alice", "data1", "read", true)
	// A request that matches no rule denies nothing, so it is allowed.
	testEnforce(t, e, "bob", "data1", "read", true)

	// An indeterminate rule must neither deny nor hide a later matched deny.
	e = newEffectTestEnforcer(t, testDenyOverride, [][]string{
		{"alice", "data1", "read", "indeterminate"},
		{"alice", "data1", "read", "deny"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)
}

func TestEffectAggregationAllowAndDeny(t *testing.T) {
	e := newEffectTestEnforcer(t, testAllowAndDeny, [][]string{
		{"alice", "data1", "read", "allow"},
		{"alice", "data1", "read", "deny"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)

	e = newEffectTestEnforcer(t, testAllowAndDeny, [][]string{
		{"alice", "data1", "read", "allow"},
		{"alice", "data1", "read", "indeterminate"},
	})
	testEnforce(t, e, "alice", "data1", "read", true)

	e = newEffectTestEnforcer(t, testAllowAndDeny, [][]string{
		{"alice", "data1", "read", "indeterminate"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)
}

func TestEffectAggregationPriorityHighestWins(t *testing.T) {
	// Lower priority number wins; a higher-priority deny overrides an allow.
	e := newExplicitPriorityEnforcer(t, [][]string{
		{"1", "alice", "data1", "read", "deny"},
		{"2", "alice", "data1", "read", "allow"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)

	// A higher-priority allow overrides a lower-priority deny.
	e = newExplicitPriorityEnforcer(t, [][]string{
		{"1", "alice", "data1", "read", "allow"},
		{"2", "alice", "data1", "read", "deny"},
	})
	testEnforce(t, e, "alice", "data1", "read", true)

	// Rules without a definite effect never decide on their own.
	e = newExplicitPriorityEnforcer(t, [][]string{
		{"1", "alice", "data1", "read", "indeterminate"},
		{"2", "alice", "data1", "read", "deny"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)

	e = newExplicitPriorityEnforcer(t, [][]string{
		{"1", "alice", "data1", "read", "indeterminate"},
	})
	testEnforce(t, e, "alice", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "read", false)
}

func TestEffectAggregationSubjectPriority(t *testing.T) {
	// The subject hierarchy places the specific user before its parent role,
	// so the user's allow outranks the role's deny.
	e, err := NewEnforcer("examples/subject_priority_model.conf", "examples/subject_priority_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "jane", "data1", "read", true)

	// The root role only has a deny rule, so it is denied conservatively.
	testEnforce(t, e, "root", "data1", "read", false)
}

func TestEffectAggregationSamePriorityConflictIsConservative(t *testing.T) {
	// Two definite rules at the same explicit priority conflict with each
	// other. The result must not depend on their insertion order.
	rules := [][]string{
		{"1", "alice", "data1", "read", "allow"},
		{"1", "alice", "data1", "read", "deny"},
	}

	e := newExplicitPriorityEnforcer(t, rules)
	testEnforce(t, e, "alice", "data1", "read", false)

	reversed := [][]string{
		{"1", "alice", "data1", "read", "deny"},
		{"1", "alice", "data1", "read", "allow"},
	}
	e = newExplicitPriorityEnforcer(t, reversed)
	testEnforce(t, e, "alice", "data1", "read", false)
}

func TestEffectAggregationPriorityWithPolicyIndex(t *testing.T) {
	// The policy-index bucket path also streams through MergeEffects, so
	// every rule must still be aggregated instead of stopping at the first
	// hit. The higher-priority allow is followed by unrelated buckets that
	// are skipped for this request, so it must not be lost before the last
	// rule is merged.
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj_type, obj, act")
	m.AddDef("p", "p", "sub, obj_type, obj, act, eft")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", testPriority)
	m.AddDef("m", "m", "g(r.sub, p.sub) && matchObj(p.obj_type, p.obj, r.obj_type, r.obj) && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	e.AddFunction("matchObj", func(args ...interface{}) (interface{}, error) {
		calls++
		pType := args[0].(string)
		pObj := args[1].(string)
		rType := args[2].(string)
		rObj := args[3].(string)
		return (pType == "*" || pType == rType) && pObj == rObj, nil
	})
	if _, err := e.AddPolicies([][]string{
		// Highest-priority rule first; the deny is lower priority.
		{"alice", "doc", "doc1", "read", "allow"},
		{"alice", "img", "img1", "read", "allow"},
		{"alice", "audio", "audio1", "read", "allow"},
		{"alice", "*", "video1", "read", "allow"},
		{"alice", "doc", "doc2", "read", "deny"},
	}); err != nil {
		t.Fatalf("AddPolicies: %v", err)
	}
	if err := e.SetPolicyIndex("p", PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			return rvals[1].(string), true
		},
		PolicyKey: func(rule []string) string {
			return rule[1]
		},
	}); err != nil {
		t.Fatal(err)
	}

	if ok, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil || !ok {
		t.Fatalf("indexed priority allow: ok=%v err=%v, want true", ok, err)
	}
	if calls != 3 {
		t.Fatalf("indexed priority evaluated %d rules, want 3", calls)
	}

	e.RemovePolicyIndex("p")
	calls = 0
	if ok, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil || !ok {
		t.Fatalf("unindexed priority allow: ok=%v err=%v, want true", ok, err)
	}
	if calls != 5 {
		t.Fatalf("unindexed priority evaluated %d rules, want 5", calls)
	}
}

func TestEffectAggregationWithoutPolicy(t *testing.T) {
	// Deny-override means "allow unless something denies"; with no policy
	// nothing can deny, so it stays allow. Every other effect denies by
	// default when no policy produces a definite allow.
	denyingEffects := []string{testAllowOverride, testAllowAndDeny, testPriority, "subjectPriority(p.eft) || deny"}
	for _, effect := range denyingEffects {
		m := model.NewModel()
		m.AddDef("r", "r", "sub, obj, act")
		m.AddDef("p", "p", "sub, obj, act")
		m.AddDef("e", "e", effect)
		m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")

		e, err := NewEnforcer(m)
		if err != nil {
			t.Fatalf("NewEnforcer for %q: %v", effect, err)
		}
		ok, err := e.Enforce("alice", "data1", "read")
		if err != nil {
			t.Fatalf("Enforce for %q: %v", effect, err)
		}
		if ok {
			t.Fatalf("effect %q with no policy: got allow, want deny", effect)
		}
	}

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", testDenyOverride)
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act")
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer for deny-override: %v", err)
	}
	if ok, err := e.Enforce("alice", "data1", "read"); err != nil || !ok {
		t.Fatalf("deny-override with no policy: ok=%v err=%v, want allow", ok, err)
	}
}
