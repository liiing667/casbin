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
	"strings"
	"testing"
)

// TestEnforceUnknownFunction pins down that a matcher naming a function the
// enforcer does not know is an error, never a silent allow or deny. This holds
// both for matchers supplied at call time and for expressions hiding in
// policies that eval() interprets.
func TestEnforceUnknownFunction(t *testing.T) {
	e, err := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}

	if _, err = e.EnforceWithMatcher("noSuchFunc(r_sub, p_sub)", "alice", "data1", "read"); err == nil {
		t.Error("EnforceWithMatcher: expected an error for an unknown function, got nil")
	}

	evalEnforcer, err := NewEnforcer("examples/eval_operator_model.conf")
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}
	if _, err = evalEnforcer.AddPolicy("noSuchFunc(r_sub)", "r_obj == 'users'", "write"); err != nil {
		t.Fatalf("AddPolicy failed: %v", err)
	}
	if _, err = evalEnforcer.Enforce("bob", "users", "write"); err == nil {
		t.Error("Enforce: expected an error for an unknown function inside eval(), got nil")
	}
}

// TestEnforceRequestSizeMismatch pins down that a request whose values do not
// line up with the request definition is rejected before any expression is
// interpreted, including for eval() matchers.
func TestEnforceRequestSizeMismatch(t *testing.T) {
	e, err := NewEnforcer("examples/eval_operator_model.conf", "examples/eval_operator_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}

	_, err = e.Enforce("admin", "users")
	if err == nil {
		t.Fatal("Enforce: expected an error for a short request, got nil")
	}
	if !strings.Contains(err.Error(), "invalid request size") {
		t.Errorf("Enforce: expected an invalid request size error, got: %v", err)
	}

	_, err = e.Enforce("admin", "users", "write", "extra")
	if err == nil {
		t.Fatal("Enforce: expected an error for an oversized request, got nil")
	}
	if !strings.Contains(err.Error(), "invalid request size") {
		t.Errorf("Enforce: expected an invalid request size error, got: %v", err)
	}
}

// TestAddFunctionRefreshesMatcherCache pins down that the function set and the
// compiled matchers stay in the same trust epoch: a function registered after
// matchers were already compiled takes effect, and decisions made with the
// previously cached matcher are unchanged.
func TestAddFunctionRefreshesMatcherCache(t *testing.T) {
	e, err := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}

	// Prime the matcher cache with the model matcher.
	testEnforce(t, e, "alice", "data1", "read", true)

	// The custom function does not exist yet: using it is an error.
	if _, err = e.EnforceWithMatcher("alwaysTrue()", "alice", "data1", "read"); err == nil {
		t.Error("EnforceWithMatcher: expected an error before the function is registered, got nil")
	}

	e.AddFunction("alwaysTrue", func(args ...interface{}) (interface{}, error) {
		return true, nil
	})

	ok, err := e.EnforceWithMatcher("alwaysTrue()", "alice", "data1", "read")
	if err != nil {
		t.Fatalf("EnforceWithMatcher: unexpected error after AddFunction: %v", err)
	}
	if !ok {
		t.Error("EnforceWithMatcher: expected allow from alwaysTrue(), got deny")
	}

	// The model matcher still decides per policy rule as before.
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

// TestEvalMatcherStaysRequestScoped pins down that an eval() matcher, which is
// bound to the request's parameters at compile time, is never shared through
// the matcher cache, and that each request is judged against its own
// attributes.
func TestEvalMatcherStaysRequestScoped(t *testing.T) {
	e, err := NewEnforcer("examples/rbac_with_abac_rule_model.conf", "examples/rbac_with_abac_rule_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer failed: %v", err)
	}

	testEnforceRBACWithABACRule(t, e, "alice", "data1", "read", testCtx{Hour: 10, Secure: true, Risk: "low"}, true)

	e.matcherMap.Range(func(key, _ interface{}) bool {
		if strings.Contains(key.(string), "eval(") {
			t.Errorf("matcher cache must not hold eval-bound expressions, found: %s", key)
		}
		return true
	})

	// Same matcher, different request context: the decision follows the
	// request, not any previously compiled state.
	testEnforceRBACWithABACRule(t, e, "alice", "data1", "read", testCtx{Hour: 20, Secure: true, Risk: "low"}, false)
	testEnforceRBACWithABACRule(t, e, "alice", "data1", "read", testCtx{Hour: 10, Secure: true, Risk: "low"}, true)
}
