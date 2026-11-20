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
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

// TestKeyMatchPathConfusionEnforce checks end to end that a request path which
// a server would resolve outside the granted prefix is denied, while the same
// prefix keeps serving its ordinary resources.
func TestKeyMatchPathConfusionEnforce(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && keyMatch2(r.obj, p.obj) && r.act == p.act")

	e, err := NewEnforcer(m, fileadapter.NewAdapter("examples/basic_policy.csv"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = e.AddPolicy("alice", "/public/*", "read"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		obj  string
		want bool
	}{
		{"/public/doc", true},
		{"/public/%E4%B8%AD%E6%96%87", true},
		{"/public/../admin", false},
		{"/public/%2e%2e/admin", false},
		{"/public/%252e%252e%252fadmin", false},
		{"/public//admin", false},
		{"/public\\..\\admin", false},
		{"/public/%5c..%5cadmin", false},
	}

	for _, tt := range tests {
		got, err := e.Enforce("alice", tt.obj, "read")
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("Enforce(alice, %q, read) = %v, want %v", tt.obj, got, tt.want)
		}
	}
}
