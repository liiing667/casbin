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
	"time"

	"github.com/casbin/casbin/v3/model"
)

func newBatchTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return e
}

func batchRequests(n int) [][]interface{} {
	requests := make([][]interface{}, n)
	for i := range requests {
		switch i % 3 {
		case 0:
			requests[i] = []interface{}{"alice", "data1", "read"}
		case 1:
			requests[i] = []interface{}{"bob", "data2", "write"}
		default:
			requests[i] = []interface{}{"jack", "data3", "read"}
		}
	}
	return requests
}

func batchExpectations(n int) []bool {
	expected := make([]bool, n)
	for i := range expected {
		expected[i] = i%3 != 2
	}
	return expected
}

func TestBatchEnforceExKeepsOriginalIndex(t *testing.T) {
	e := newBatchTestEnforcer(t)
	const n = 64

	results, err := e.BatchEnforceEx(context.Background(), batchRequests(n))
	if err != nil {
		t.Fatalf("BatchEnforceEx returned error: %v", err)
	}
	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}

	expected := batchExpectations(n)
	for index, result := range results {
		if result.Index != index {
			t.Fatalf("slot %d carries index %d", index, result.Index)
		}
		if result.Canceled {
			t.Fatalf("request %d must not be canceled", index)
		}
		if result.Err != nil {
			t.Fatalf("request %d returned unexpected error: %v", index, result.Err)
		}
		if result.Allowed != expected[index] {
			t.Fatalf("request %d: expected allow=%v, got %v", index, expected[index], result.Allowed)
		}
	}
}

func TestBatchEnforceExMatchesSingleAndSequentialBatch(t *testing.T) {
	e := newBatchTestEnforcer(t)
	requests := batchRequests(24)
	expected := batchExpectations(len(requests))

	for index, request := range requests {
		allowed, err := e.Enforce(request...)
		if err != nil {
			t.Fatalf("Enforce(%d): %v", index, err)
		}
		if allowed != expected[index] {
			t.Fatalf("Enforce(%d): expected %v, got %v", index, expected[index], allowed)
		}
	}

	sequential, err := e.BatchEnforce(requests)
	if err != nil {
		t.Fatalf("BatchEnforce: %v", err)
	}

	results, err := e.BatchEnforceEx(context.Background(), requests)
	if err != nil {
		t.Fatalf("BatchEnforceEx: %v", err)
	}

	for index := range requests {
		if results[index].Allowed != sequential[index] || results[index].Allowed != expected[index] {
			t.Fatalf("request %d: single=%v batch=%v ex=%v", index, expected[index], sequential[index], results[index].Allowed)
		}
	}
}

func TestBatchEnforceExSingleItemErrorKeepsAlignment(t *testing.T) {
	e := newBatchTestEnforcer(t)
	requests := [][]interface{}{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"only", "two"}, // invalid arity for this model
		{"jack", "data3", "read"},
		{"alice", "data1", "read"},
	}

	results, err := e.BatchEnforceEx(context.Background(), requests)
	if err != nil {
		t.Fatalf("BatchEnforceEx must not return a batch-level error: %v", err)
	}
	if len(results) != len(requests) {
		t.Fatalf("expected %d results, got %d", len(requests), len(results))
	}

	expectedAllowed := []bool{true, true, false, false, true}
	expectedError := []bool{false, false, true, false, false}
	for index := range requests {
		if results[index].Index != index {
			t.Fatalf("slot %d carries index %d", index, results[index].Index)
		}
		if results[index].Canceled {
			t.Fatalf("request %d must not be canceled", index)
		}
		if (results[index].Err != nil) != expectedError[index] {
			t.Fatalf("request %d: expected error=%v, got %v", index, expectedError[index], results[index].Err)
		}
		if results[index].Err == nil && results[index].Allowed != expectedAllowed[index] {
			t.Fatalf("request %d: expected allow=%v, got %v", index, expectedAllowed[index], results[index].Allowed)
		}
	}

	if _, err := e.BatchEnforce(requests); err == nil {
		t.Fatal("sequential BatchEnforce still reports the single item error")
	}
}

func TestBatchEnforceExCanceledRequestsAreNotDecisions(t *testing.T) {
	e := newBatchTestEnforcer(t)
	requests := batchRequests(24)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := e.BatchEnforceEx(ctx, requests)
	if err != nil {
		t.Fatalf("BatchEnforceEx: %v", err)
	}
	if len(results) != len(requests) {
		t.Fatalf("expected %d results, got %d", len(requests), len(results))
	}

	for index, result := range results {
		if result.Index != index {
			t.Fatalf("slot %d carries index %d", index, result.Index)
		}
		if !result.Canceled {
			t.Fatalf("request %d must be canceled", index)
		}
		if !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("request %d: expected context.Canceled, got %v", index, result.Err)
		}
	}
}

func TestBatchEnforceExTimeoutMarksUndecidedRequests(t *testing.T) {
	e := newBatchTestEnforcer(t)
	const n = 64

	entered := make(chan struct{}, n)
	release := make(chan struct{})
	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = blockingMatcher() && r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	if err := e.InitWithModelAndAdapter(m, e.adapter); err != nil {
		t.Fatalf("InitWithModelAndAdapter: %v", err)
	}
	e.AddFunction("blockingMatcher", func(arguments ...interface{}) (interface{}, error) {
		entered <- struct{}{}
		<-release
		return true, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	var results []BatchEnforceResult
	var batchErr error
	go func() {
		results, batchErr = e.BatchEnforceEx(ctx, batchRequests(n))
		close(done)
	}()

	<-entered // at least one worker is blocked inside enforce
	cancel()

	select {
	case <-done:
		t.Fatal("batch must wait for in-flight requests to finish before returning")
	default:
	}

	close(release)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("BatchEnforceEx did not return after release")
	}

	if batchErr != nil {
		t.Fatalf("BatchEnforceEx: %v", batchErr)
	}
	if len(results) != n {
		t.Fatalf("expected %d results, got %d", n, len(results))
	}

	canceledCount := 0
	decidedCount := 0
	for index, result := range results {
		if result.Index != index {
			t.Fatalf("slot %d carries index %d", index, result.Index)
		}
		if result.Canceled {
			canceledCount++
			if !errors.Is(result.Err, context.Canceled) {
				t.Fatalf("request %d: expected context.Canceled, got %v", index, result.Err)
			}
			continue
		}
		decidedCount++
		if result.Err != nil {
			t.Fatalf("request %d: unexpected error %v", index, result.Err)
		}
	}

	if canceledCount == 0 {
		t.Fatal("expected at least one undecided request to be marked canceled")
	}
	if canceledCount+decidedCount != n {
		t.Fatalf("every request must be either decided or canceled, got %d decided and %d canceled", decidedCount, canceledCount)
	}
}

func TestBatchEnforceExOutOfOrderCompletion(t *testing.T) {
	e := newBatchTestEnforcer(t)
	const n = 100

	// Earlier requests take longer, so completion order is the reverse of
	// dispatch order while each slot must still map back to its own index.
	requests := make([][]interface{}, n)
	for i := range requests {
		requests[i] = []interface{}{float64(i), "data", "read"}
	}

	modelText := `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = delayProbe(r.sub) && r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}
	if err := e.InitWithModelAndAdapter(m, e.adapter); err != nil {
		t.Fatalf("InitWithModelAndAdapter: %v", err)
	}
	e.AddFunction("delayProbe", func(arguments ...interface{}) (interface{}, error) {
		index, ok := arguments[0].(float64)
		if !ok {
			return nil, errors.New("delayProbe expects a numeric request index")
		}
		time.Sleep(time.Duration(n-int(index)) * time.Millisecond)
		return true, nil
	})

	results, err := e.BatchEnforceEx(context.Background(), requests)
	if err != nil {
		t.Fatalf("BatchEnforceEx: %v", err)
	}

	for index, result := range results {
		if result.Index != index {
			t.Fatalf("slot %d carries index %d", index, result.Index)
		}
		if result.Canceled || result.Err != nil {
			t.Fatalf("request %d must have an independent decision, got canceled=%v err=%v", index, result.Canceled, result.Err)
		}
	}
}

func TestBatchEnforceExWithMatcher(t *testing.T) {
	e := newBatchTestEnforcer(t)
	requests := [][]interface{}{
		{"alice", "data1", "read"},
		{"alice", "data1", "write"},
	}
	matcher := "r.sub == p.sub && r.obj == p.obj && r.act == p.act"

	results, err := e.BatchEnforceExWithMatcher(context.Background(), matcher, requests)
	if err != nil {
		t.Fatalf("BatchEnforceExWithMatcher: %v", err)
	}

	expected, err := e.BatchEnforceWithMatcher(matcher, requests)
	if err != nil {
		t.Fatalf("BatchEnforceWithMatcher: %v", err)
	}

	for index := range requests {
		if results[index].Index != index || results[index].Err != nil || results[index].Allowed != expected[index] {
			t.Fatalf("request %d: expected %v, got %+v", index, expected[index], results[index])
		}
	}
}

func TestBatchEnforceExEmptyAndNilContext(t *testing.T) {
	e := newBatchTestEnforcer(t)

	results, err := e.BatchEnforceEx(context.Background(), nil)
	if err != nil || len(results) != 0 {
		t.Fatalf("empty batch: expected empty result, got results=%v err=%v", results, err)
	}

	if _, err := e.BatchEnforceEx(nil, batchRequests(1)); err == nil {
		t.Fatal("nil context must return an error")
	}
}

func TestBatchEnforceExInterfaceAndSyncedEnforcer(t *testing.T) {
	var _ IEnforcer = (*Enforcer)(nil)

	e, err := NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewSyncedEnforcer: %v", err)
	}

	requests := batchRequests(16)
	results, err := e.BatchEnforceEx(context.Background(), requests)
	if err != nil {
		t.Fatalf("SyncedEnforcer.BatchEnforceEx: %v", err)
	}

	expected := batchExpectations(len(requests))
	for index := range requests {
		if results[index].Index != index || results[index].Canceled || results[index].Err != nil {
			t.Fatalf("unexpected result at %d: %+v", index, results[index])
		}
		if results[index].Allowed != expected[index] {
			t.Fatalf("request %d: expected %v, got %v", index, expected[index], results[index].Allowed)
		}
	}
}
