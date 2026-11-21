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

package effector

import (
	"testing"

	"github.com/casbin/casbin/v3/constant"
)

// merge runs MergeEffects the same way the enforcer does: once per policy,
// streaming in the effects and matches in policy order.
func merge(t *testing.T, expr string, effects []Effect, matches []float64) (Effect, int) {
	t.Helper()
	e := NewDefaultEffector()
	result := Indeterminate
	explainIndex := -1
	for i := range effects {
		var err error
		result, explainIndex, err = e.MergeEffects(expr, effects, matches, i, len(effects))
		if err != nil {
			t.Fatalf("MergeEffects at %d: %v", i, err)
		}
	}
	return result, explainIndex
}

func TestMergeEffectsAllowOverride(t *testing.T) {
	// A later allow still wins when an earlier rule denies; the deny rule on
	// its own must not produce an allow.
	if result, _ := merge(t, constant.AllowOverrideEffect,
		[]Effect{Deny, Allow}, []float64{1, 1}); result != Allow {
		t.Fatalf("deny then allow: got %v, want Allow", result)
	}
	if result, _ := merge(t, constant.AllowOverrideEffect,
		[]Effect{Deny, Indeterminate}, []float64{1, 1}); result != Indeterminate {
		t.Fatalf("only deny: got %v, want Indeterminate", result)
	}
	if result, _ := merge(t, constant.AllowOverrideEffect,
		[]Effect{Indeterminate, Allow}, []float64{1, 1}); result != Allow {
		t.Fatalf("indeterminate then allow: got %v, want Allow", result)
	}
}

func TestMergeEffectsDenyOverride(t *testing.T) {
	if result, _ := merge(t, constant.DenyOverrideEffect,
		[]Effect{Allow, Deny}, []float64{1, 1}); result != Deny {
		t.Fatalf("allow then deny: got %v, want Deny", result)
	}
	if result, _ := merge(t, constant.DenyOverrideEffect,
		[]Effect{Allow, Allow}, []float64{1, 1}); result != Allow {
		t.Fatalf("only allow: got %v, want Allow", result)
	}
	if result, _ := merge(t, constant.DenyOverrideEffect,
		[]Effect{Indeterminate, Deny}, []float64{1, 1}); result != Deny {
		t.Fatalf("indeterminate then deny: got %v, want Deny", result)
	}
	// No matched rule means nothing denies, so the default is allow.
	if result, _ := merge(t, constant.DenyOverrideEffect,
		[]Effect{Allow, Deny}, []float64{0, 0}); result != Allow {
		t.Fatalf("no match: got %v, want Allow", result)
	}
}

func TestMergeEffectsAllowAndDeny(t *testing.T) {
	if result, _ := merge(t, constant.AllowAndDenyEffect,
		[]Effect{Allow, Deny}, []float64{1, 1}); result != Deny {
		t.Fatalf("allow then deny: got %v, want Deny", result)
	}
	if result, index := merge(t, constant.AllowAndDenyEffect,
		[]Effect{Allow, Allow}, []float64{1, 1}); result != Allow || index != 0 {
		t.Fatalf("only allow: got %v index %d, want Allow index 0", result, index)
	}
	if result, _ := merge(t, constant.AllowAndDenyEffect,
		[]Effect{Allow, Indeterminate}, []float64{1, 1}); result != Allow {
		t.Fatalf("allow then indeterminate: got %v, want Allow", result)
	}
}

func TestMergeEffectsPriorityAggregatesAllHits(t *testing.T) {
	tests := []struct {
		name    string
		effects []Effect
		matches []float64
		want    Effect
	}{
		// Policies are ordered highest priority first, so the first matched
		// definite rule is authoritative regardless of later rules.
		{"allow then deny", []Effect{Allow, Deny}, []float64{1, 1}, Allow},
		{"deny then allow", []Effect{Deny, Allow}, []float64{1, 1}, Deny},
		// Indeterminate rules never override a definite decision.
		{"indeterminate then deny", []Effect{Indeterminate, Deny}, []float64{1, 1}, Deny},
		{"indeterminate then allow", []Effect{Indeterminate, Allow}, []float64{1, 1}, Allow},
		{"allow then indeterminate", []Effect{Allow, Indeterminate}, []float64{1, 1}, Allow},
		// No definite rule leaves the decision unresolved, which the
		// enforcer treats conservatively as deny.
		{"only indeterminate", []Effect{Indeterminate, Indeterminate}, []float64{1, 1}, Indeterminate},
		{"no match", []Effect{Allow, Deny}, []float64{0, 0}, Indeterminate},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if result, _ := merge(t, constant.PriorityEffect, test.effects, test.matches); result != test.want {
				t.Fatalf("got %v, want %v", result, test.want)
			}
			if result, _ := merge(t, constant.SubjectPriorityEffect, test.effects, test.matches); result != test.want {
				t.Fatalf("subjectPriority got %v, want %v", result, test.want)
			}
		})
	}
}

func TestMergeEffectsPriorityDefersDecisionToLastRule(t *testing.T) {
	e := NewDefaultEffector()
	effects := []Effect{Allow, Deny}
	matches := []float64{1, 1}

	// A definite first hit must not be returned while more rules are pending,
	// otherwise the enforcer would short-circuit before aggregating them.
	result, _, err := e.MergeEffects(constant.PriorityEffect, effects, matches, 0, 2)
	if err != nil {
		t.Fatalf("MergeEffects at 0: %v", err)
	}
	if result != Indeterminate {
		t.Fatalf("intermediate result: got %v, want Indeterminate", result)
	}

	result, index, err := e.MergeEffects(constant.PriorityEffect, effects, matches, 1, 2)
	if err != nil {
		t.Fatalf("MergeEffects at 1: %v", err)
	}
	if result != Allow || index != 0 {
		t.Fatalf("final result: got %v index %d, want Allow index 0", result, index)
	}
}

func TestMergeEffectsUnsupportedExpr(t *testing.T) {
	e := NewDefaultEffector()
	if result, _, err := e.MergeEffects("unsupported", []Effect{Allow}, []float64{1}, 0, 1); err == nil || result != Deny {
		t.Fatalf("got result %v err %v, want Deny with an error", result, err)
	}
}
