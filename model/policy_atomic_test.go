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

package model

import (
	"reflect"
	"strings"
	"testing"
)

const atomicAddPoliciesTestModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

func TestRegressionAddPoliciesSecondBatchFailure(t *testing.T) {
	m, err := NewModelFromString(atomicAddPoliciesTestModel)
	if err != nil {
		t.Fatal(err)
	}

	first := [][]string{{"alice", "data1", "read"}}
	affected, err := m.AddPoliciesWithAffected("p", "p", first)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(affected, first) {
		t.Fatalf("first affected = %v, want %v", affected, first)
	}

	second := [][]string{
		{"bob", "data2", "write"},
		{"malformed"},
	}
	if _, err := m.AddPoliciesWithAffected("p", "p", second); err == nil {
		t.Fatal("expected malformed second rule to fail")
	}

	policies, err := m.GetPolicy("p", "p")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policies, first) {
		t.Fatalf("policy after failed batch = %v, want %v", policies, first)
	}
	if _, ok := m["p"]["p"].PolicyMap["bob,data2,write"]; ok {
		t.Fatal("partially inserted rule leaked into the policy index")
	}

	validSecond := [][]string{{"bob", "data2", "write"}, {"carol", "data3", "read"}}
	affected, err = m.AddPoliciesWithAffected("p", "p", validSecond)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(affected, validSecond) {
		t.Fatalf("retry affected = %v, want %v", affected, validSecond)
	}

	affected, err = m.AddPoliciesWithAffected("p", "p", validSecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(affected) != 0 {
		t.Fatalf("retry affected = %v, want no changes", affected)
	}

	policies, _ = m.GetPolicy("p", "p")
	want := append(append([][]string{}, first...), validSecond...)
	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("final policy = %v, want %v", policies, want)
	}
}

func TestRegressionAddPoliciesDuplicateRules(t *testing.T) {
	m, err := NewModelFromString(atomicAddPoliciesTestModel)
	if err != nil {
		t.Fatal(err)
	}

	existing := []string{"alice", "data1", "read"}
	if _, err := m.AddPoliciesWithAffected("p", "p", [][]string{existing}); err != nil {
		t.Fatal(err)
	}

	rules := [][]string{
		{"bob", "data2", "read"},
		existing,
		{"bob", "data2", "read"},
		{"carol", "data3", "write"},
		{"carol", "data3", "write"},
	}
	affected, err := m.AddPoliciesWithAffected("p", "p", rules)
	if err != nil {
		t.Fatal(err)
	}
	wantAffected := [][]string{
		{"bob", "data2", "read"},
		{"carol", "data3", "write"},
	}
	if !reflect.DeepEqual(affected, wantAffected) {
		t.Fatalf("affected = %v, want %v", affected, wantAffected)
	}

	policies, _ := m.GetPolicy("p", "p")
	wantPolicies := [][]string{
		existing,
		{"bob", "data2", "read"},
		{"carol", "data3", "write"},
	}
	if !reflect.DeepEqual(policies, wantPolicies) {
		t.Fatalf("policy = %v, want %v", policies, wantPolicies)
	}
}

func TestRegressionAddPoliciesPriorityOrder(t *testing.T) {
	m, err := NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = priority, sub, obj, act, eft

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatal(err)
	}
	rules := [][]string{
		{"3", "alice", "data1", "read", "allow"},
		{"1", "alice", "data1", "read", "deny"},
		{"2", "alice", "data1", "read", "allow"},
		{"2", "alice", "data1", "read", "allow"},
	}
	affected, err := m.AddPoliciesWithAffected("p", "p", rules)
	if err != nil {
		t.Fatal(err)
	}
	if len(affected) != 3 {
		t.Fatalf("affected = %v, want 3 unique rules", affected)
	}

	policies, _ := m.GetPolicy("p", "p")
	want := [][]string{
		{"1", "alice", "data1", "read", "deny"},
		{"2", "alice", "data1", "read", "allow"},
		{"3", "alice", "data1", "read", "allow"},
	}
	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("policy = %v, want priority order %v", policies, want)
	}
	for i, rule := range want {
		key := strings.Join(rule, DefaultSep)
		if m["p"]["p"].PolicyMap[key] != i {
			t.Fatalf("PolicyMap[%s] = %d, want %d", key, m["p"]["p"].PolicyMap[key], i)
		}
	}
}
