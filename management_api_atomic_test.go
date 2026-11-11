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
	"reflect"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/rbac"
)

type atomicRollbackBatchAdapter struct {
	rules        [][]string
	failNext     bool
	partialWrite bool
}

func (a *atomicRollbackBatchAdapter) LoadPolicy(m model.Model) error {
	for _, rule := range a.rules {
		if err := m.AddPolicy("p", "p", rule); err != nil {
			return err
		}
	}
	return nil
}

func (a *atomicRollbackBatchAdapter) SavePolicy(m model.Model) error {
	a.rules = nil
	policies, err := m.GetPolicy("p", "p")
	if err != nil {
		return err
	}
	for _, rule := range policies {
		a.rules = append(a.rules, append([]string(nil), rule...))
	}
	return nil
}

func (a *atomicRollbackBatchAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicies(sec, ptype, [][]string{rule})
}

func (a *atomicRollbackBatchAdapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	if a.failNext {
		a.failNext = false
		if a.partialWrite && len(rules) != 0 {
			a.rules = append(a.rules, append([]string(nil), rules[0]...))
		}
		return errors.New("adapter write failed")
	}
	for _, rule := range rules {
		a.rules = append(a.rules, append([]string(nil), rule...))
	}
	return nil
}

func (a *atomicRollbackBatchAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicies(sec, ptype, [][]string{rule})
}

func (a *atomicRollbackBatchAdapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	remove := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		remove[strings.Join(rule, model.DefaultSep)] = struct{}{}
	}

	kept := a.rules[:0]
	for _, rule := range a.rules {
		if _, ok := remove[strings.Join(rule, model.DefaultSep)]; !ok {
			kept = append(kept, rule)
		}
	}
	a.rules = kept
	return nil
}

func (a *atomicRollbackBatchAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}

var _ persist.BatchAdapter = (*atomicRollbackBatchAdapter)(nil)

type atomicFailOnRoleManager struct {
	rbac.RoleManager
	failOn string
}

func (m *atomicFailOnRoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	if name2 == m.failOn {
		return errors.New("role link failed")
	}
	return m.RoleManager.AddLink(name1, name2, domain...)
}

func TestRegressionAddPoliciesAdapterFailure(t *testing.T) {
	adapter := &atomicRollbackBatchAdapter{}
	e, err := NewEnforcer("examples/basic_model.conf", adapter)
	if err != nil {
		t.Fatal(err)
	}

	first := [][]string{{"alice", "data1", "read"}}
	if added, err := e.AddPolicies(first); err != nil || !added {
		t.Fatalf("first batch: added=%v err=%v", added, err)
	}

	adapter.failNext = true
	adapter.partialWrite = true
	second := [][]string{
		{"bob", "data2", "write"},
		{"carol", "data3", "read"},
	}
	if added, err := e.AddPolicies(second); err == nil || added {
		t.Fatalf("second batch should fail without adding: added=%v err=%v", added, err)
	}

	policies, _ := e.GetPolicy()
	if !reflect.DeepEqual(policies, first) {
		t.Fatalf("policy after adapter failure = %v, want %v", policies, first)
	}
	if !reflect.DeepEqual(adapter.rules, first) {
		t.Fatalf("storage after adapter failure = %v, want %v", adapter.rules, first)
	}

	if added, err := e.AddPolicies(second); err != nil || !added {
		t.Fatalf("retry: added=%v err=%v", added, err)
	}
	want := [][]string{first[0], second[0], second[1]}
	policies, _ = e.GetPolicy()
	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("policy after retry = %v, want %v", policies, want)
	}
	if !reflect.DeepEqual(adapter.rules, want) {
		t.Fatalf("storage after retry = %v, want %v", adapter.rules, want)
	}

	// Repeating a batch with duplicate and existing rules must not write
	// anything new to either the model or the adapter.
	duplicates := [][]string{second[0], second[0], first[0]}
	if added, err := e.AddPoliciesEx(duplicates); err != nil || !added {
		t.Fatalf("duplicate batch: added=%v err=%v", added, err)
	}
	policies, _ = e.GetPolicy()
	if !reflect.DeepEqual(policies, want) {
		t.Fatalf("duplicate batch changed policy to %v", policies)
	}
	if !reflect.DeepEqual(adapter.rules, want) {
		t.Fatalf("duplicate batch changed storage to %v", adapter.rules)
	}
}

func TestRegressionGroupingPolicyRoleLinkFailure(t *testing.T) {
	e, err := NewEnforcer("examples/rbac_model.conf")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRoleManager(&atomicFailOnRoleManager{RoleManager: e.GetRoleManager(), failOn: "forbidden"})

	if added, err := e.AddGroupingPolicy("alice", "admin"); err != nil || !added {
		t.Fatalf("existing grouping policy: added=%v err=%v", added, err)
	}

	rules := [][]string{
		{"bob", "user"},
		{"carol", "forbidden"},
	}
	if added, err := e.AddGroupingPolicies(rules); err == nil || added {
		t.Fatalf("role-link failure should not add: added=%v err=%v", added, err)
	}

	policies, _ := e.GetGroupingPolicy()
	if !reflect.DeepEqual(policies, [][]string{{"alice", "admin"}}) {
		t.Fatalf("grouping policy = %v, want only the original link", policies)
	}
	if has, err := e.HasRoleForUser("alice", "admin"); err != nil || !has {
		t.Fatalf("original role link was lost: has=%v err=%v", has, err)
	}
	if has, err := e.HasRoleForUser("bob", "user"); err != nil || has {
		t.Fatalf("partially added role link leaked: has=%v err=%v", has, err)
	}
}
