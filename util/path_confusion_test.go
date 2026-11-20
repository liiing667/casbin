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

package util

import (
	"testing"
)

// confusedKeys are out-of-bounds aliases: each string is resolved by a
// downstream HTTP server, framework, or filesystem to a path outside
// "/public/", so no KeyMatch-family matcher may approve it under "/public/*"
// (or any other pattern, including the bare "*" wildcard).
var confusedKeys = []struct {
	name string
	key1 string
}{
	// Encoded dot segments: the server decodes them to ".." after the match.
	{"encoded dotdot", "/public/%2e%2e/admin"},
	{"encoded dotdot upper", "/public/%2E%2E/admin"},
	{"encoded dotdot half left", "/public/.%2e/admin"},
	{"encoded dotdot half right", "/public/%2e./admin"},
	{"encoded dotdot and slash", "/public/%2e%2e%2fadmin"},
	{"literal dotdot encoded slash", "/public/..%2fadmin"},
	{"double encoded dotdot", "/public/%252e%252e%252fadmin"},
	{"overlong utf8 dots", "/public/%c0%ae%c0%ae/admin"},
	{"invalid escape", "/public/%zz/admin"},
	{"dangling percent", "/public/%"},
	{"short escape", "/public/%2"},
	{"encoded nul", "/public/%00/admin"},
	{"raw nul", "/public/\x00/admin"},

	// Repeated slashes: collapsed by servers, so the routed path differs.
	{"double slash", "/public//admin"},
	{"double slash with dotdot", "/public//../admin"},

	// Backslashes: path separators on Windows.
	{"backslash dotdot", "/public\\..\\admin"},
	{"encoded backslash dotdot", "/public/%5c..%5cadmin"},
	{"backslash separator", "/public\\admin"},

	// Literal dot segments and their Windows-normalized aliases.
	{"dotdot", "/public/../admin"},
	{"dot", "/public/./admin"},
	{"trailing dotdot", "/public/.."},
	{"trailing dot", "/public/."},
	{"triple dot", "/public/.../admin"},
	{"dotdot trailing space", "/public/.. /admin"},
	{"encoded dotdot trailing space", "/public/%2e%2e%20/admin"},
}

// TestPathConfusionRejected pins the fail-closed contract: every matcher
// rejects every out-of-bounds alias even though the raw string sits under the
// protected prefix and would have matched before.
func TestPathConfusionRejected(t *testing.T) {
	for _, c := range confusedKeys {
		t.Run(c.name, func(t *testing.T) {
			if KeyMatch(c.key1, "/public/*") {
				t.Errorf("KeyMatch(%q, /public/*) = true, want false", c.key1)
			}
			if KeyMatch(c.key1, "*") {
				t.Errorf("KeyMatch(%q, *) = true, want false", c.key1)
			}
			if KeyMatch2(c.key1, "/public/*") {
				t.Errorf("KeyMatch2(%q, /public/*) = true, want false", c.key1)
			}
			if KeyMatch2(c.key1, "*") {
				t.Errorf("KeyMatch2(%q, *) = true, want false", c.key1)
			}
			if KeyMatch3(c.key1, "/public/*") {
				t.Errorf("KeyMatch3(%q, /public/*) = true, want false", c.key1)
			}
			if KeyMatch4(c.key1, "/public/*") {
				t.Errorf("KeyMatch4(%q, /public/*) = true, want false", c.key1)
			}
			if KeyMatch5(c.key1, "/public/*") {
				t.Errorf("KeyMatch5(%q, /public/*) = true, want false", c.key1)
			}
			if matched, err := GlobMatch(c.key1, "/public/**"); err != nil || matched {
				t.Errorf("GlobMatch(%q, /public/**) = %v, %v; want false, nil", c.key1, matched, err)
			}
			if got := KeyGet(c.key1, "/public/*"); got != "" {
				t.Errorf("KeyGet(%q, /public/*) = %q, want \"\"", c.key1, got)
			}
			if got := KeyGet2(c.key1, "/public/:res", "res"); got != "" {
				t.Errorf("KeyGet2(%q, /public/:res, res) = %q, want \"\"", c.key1, got)
			}
			if got := KeyGet3(c.key1, "/public/{res}", "res"); got != "" {
				t.Errorf("KeyGet3(%q, /public/{res}, res) = %q, want \"\"", c.key1, got)
			}
		})
	}
}

// legitEncodedKeys hold percent-encoding that decodes to harmless names; the
// match must survive so that legal wildcards keep working for real resources.
var legitEncodedKeys = []struct {
	name string
	key1 string
}{
	{"utf8 name", "/public/%E4%B8%AD%E6%96%87"},
	{"encoded letter", "/public/%41dmin"},
	{"encoded space", "/public/a%20b"},
	{"encoded plus", "/public/x%2By"},
	{"dotfile", "/public/.well-known/thing"},
	{"leading dotdot name", "/public/..foo/bar"},
	{"trailing dotdot name", "/public/foo..bar"},
}

func TestLegitEncodedKeysStillMatch(t *testing.T) {
	for _, c := range legitEncodedKeys {
		t.Run(c.name, func(t *testing.T) {
			if !KeyMatch(c.key1, "/public/*") {
				t.Errorf("KeyMatch(%q, /public/*) = false, want true", c.key1)
			}
			if !KeyMatch2(c.key1, "/public/*") {
				t.Errorf("KeyMatch2(%q, /public/*) = false, want true", c.key1)
			}
			if !KeyMatch3(c.key1, "/public/*") {
				t.Errorf("KeyMatch3(%q, /public/*) = false, want true", c.key1)
			}
			if !KeyMatch4(c.key1, "/public/*") {
				t.Errorf("KeyMatch4(%q, /public/*) = false, want true", c.key1)
			}
			if !KeyMatch5(c.key1, "/public/*") {
				t.Errorf("KeyMatch5(%q, /public/*) = false, want true", c.key1)
			}
			if matched, err := GlobMatch(c.key1, "/public/**"); err != nil || !matched {
				t.Errorf("GlobMatch(%q, /public/**) = %v, %v; want true, nil", c.key1, matched, err)
			}
		})
	}
}

// TestTrailingSlashComparison pins the existing trailing-slash semantics: a
// trailing slash is an ordinary character, compared item by item.
func TestTrailingSlashComparison(t *testing.T) {
	tests := []struct {
		key1 string
		key2 string
		res  bool
	}{
		{"/public/", "/public/*", true},
		{"/public/", "/public/", true},
		{"/public", "/public/", false},
		{"/public/x/", "/public/*", true},
		{"/public/x/", "/public/x", false},
	}
	for _, tt := range tests {
		if res := KeyMatch(tt.key1, tt.key2); res != tt.res {
			t.Errorf("KeyMatch(%q, %q) = %v, want %v", tt.key1, tt.key2, res, tt.res)
		}
		if res := KeyMatch2(tt.key1, tt.key2); res != tt.res {
			t.Errorf("KeyMatch2(%q, %q) = %v, want %v", tt.key1, tt.key2, res, tt.res)
		}
		if res := KeyMatch3(tt.key1, tt.key2); res != tt.res {
			t.Errorf("KeyMatch3(%q, %q) = %v, want %v", tt.key1, tt.key2, res, tt.res)
		}
		if res := KeyMatch4(tt.key1, tt.key2); res != tt.res {
			t.Errorf("KeyMatch4(%q, %q) = %v, want %v", tt.key1, tt.key2, res, tt.res)
		}
		if res := KeyMatch5(tt.key1, tt.key2); res != tt.res {
			t.Errorf("KeyMatch5(%q, %q) = %v, want %v", tt.key1, tt.key2, res, tt.res)
		}
	}
}

// TestQueryStringComparison pins query-string handling: KeyMatch5 strips the
// query before matching and before the path-confusion check, so the query may
// hold anything; the other matchers treat "?" as an ordinary character.
func TestQueryStringComparison(t *testing.T) {
	// KeyMatch5: the path part decides, the query is free-form.
	if !KeyMatch5("/public/x?y=1", "/public/x") {
		t.Error("KeyMatch5(/public/x?y=1, /public/x) = false, want true")
	}
	if !KeyMatch5("/public/x?next=/../admin", "/public/x") {
		t.Error("KeyMatch5(/public/x?next=/../admin, /public/x) = false, want true")
	}
	if !KeyMatch5("/public/x?next=%2e%2e%2fadmin", "/public/x") {
		t.Error("KeyMatch5(/public/x?next=%2e%2e%2fadmin, /public/x) = false, want true")
	}
	if KeyMatch5("/public/../admin?x=1", "/public/*") {
		t.Error("KeyMatch5(/public/../admin?x=1, /public/*) = true, want false")
	}
	if KeyMatch5("/public/%2e%2e/admin?x=1", "/public/*") {
		t.Error("KeyMatch5(/public/%2e%2e/admin?x=1, /public/*) = true, want false")
	}

	// KeyMatch/KeyMatch2: "?" is literal, compared item by item.
	if !KeyMatch("/public/x?y=1", "/public/*") {
		t.Error("KeyMatch(/public/x?y=1, /public/*) = false, want true")
	}
	if KeyMatch("/public/x?y=1", "/public/x") {
		t.Error("KeyMatch(/public/x?y=1, /public/x) = true, want false")
	}
	if KeyMatch2("/public/x?y=1", "/public/x") {
		t.Error("KeyMatch2(/public/x?y=1, /public/x) = true, want false")
	}
	if !KeyMatch2("/public/x?y=1", "/public/*") {
		t.Error("KeyMatch2(/public/x?y=1, /public/*) = false, want true")
	}
}

// TestCaptureGroupsInPatternPreserved pins the documented support for key2
// patterns that carry their own capture groups: token extraction must keep
// addressing the pattern variables, not the pattern's own groups.
func TestCaptureGroupsInPatternPreserved(t *testing.T) {
	if !KeyMatch2("/a/123", "/(a|b)/:id") {
		t.Error("KeyMatch2(/a/123, /(a|b)/:id) = false, want true")
	}
	if KeyMatch2("/c/123", "/(a|b)/:id") {
		t.Error("KeyMatch2(/c/123, /(a|b)/:id) = true, want false")
	}
	if got := KeyGet2("/a/123", "/(a|b)/:id", "id"); got != "123" {
		t.Errorf("KeyGet2(/a/123, /(a|b)/:id, id) = %q, want 123", got)
	}
	if got := KeyGet3("/a/x/123", "/(a|b)/x/{id}", "id"); got != "123" {
		t.Errorf("KeyGet3(/a/x/123, /(a|b)/x/{id}, id) = %q, want 123", got)
	}
	if !KeyMatch4("/parent/123/child/123", "/parent/{id}/child/{id}") {
		t.Error("KeyMatch4 repeated token mismatch: want true")
	}
	if KeyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}") {
		t.Error("KeyMatch4 repeated token mismatch: want false")
	}
}

// TestNormalPathsUnaffected spot-checks that ordinary paths, legal wildcards,
// and domain-style keys behave exactly as before.
func TestNormalPathsUnaffected(t *testing.T) {
	tests := []struct {
		key1 string
		key2 string
		res  bool
	}{
		{"/foo", "/foo", true},
		{"/foo/bar", "/foo/*", true},
		{"/foobar", "/foo/*", false},
		{"acme.com", "*", true},
		{"team/123", "*", true},
	}
	for _, tt := range tests {
		if res := KeyMatch(tt.key1, tt.key2); res != tt.res {
			t.Errorf("KeyMatch(%q, %q) = %v, want %v", tt.key1, tt.key2, res, tt.res)
		}
		if res := KeyMatch2(tt.key1, tt.key2); res != tt.res {
			t.Errorf("KeyMatch2(%q, %q) = %v, want %v", tt.key1, tt.key2, res, tt.res)
		}
	}

	if !KeyMatch2("/myid/using/myresid", "/:id/using/:resId") {
		t.Error("KeyMatch2(/myid/using/myresid, /:id/using/:resId) = false, want true")
	}
	if !KeyMatch3("/myid/using/myresid", "/{id}/using/{resId}") {
		t.Error("KeyMatch3(/myid/using/myresid, /{id}/using/{resId}) = false, want true")
	}
	if got := KeyGet("/foo/bar/foo", "/foo/*"); got != "bar/foo" {
		t.Errorf("KeyGet(/foo/bar/foo, /foo/*) = %q, want bar/foo", got)
	}
	if got := KeyGet2("/resource1", "/:resource", "resource"); got != "resource1" {
		t.Errorf("KeyGet2(/resource1, /:resource, resource) = %q, want resource1", got)
	}
	if got := KeyGet3("project/proj_project1_admin/", "project/proj_{project}_admin/", "project"); got != "project1" {
		t.Errorf("KeyGet3(...) = %q, want project1", got)
	}
	if matched, err := GlobMatch("/public/a/b", "/public/**"); err != nil || !matched {
		t.Errorf("GlobMatch(/public/a/b, /public/**) = %v, %v; want true, nil", matched, err)
	}
}
