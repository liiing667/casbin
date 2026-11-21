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
	"sync"
)

// batchEnforceConcurrency is the maximum number of enforcement requests
// evaluated concurrently by BatchEnforceEx.
const batchEnforceConcurrency = 8

// BatchEnforceResult is the independent outcome of a single request inside a
// batch. Index keeps the request's original position even when workers finish
// out of order, so results never shift because of an error or a cancellation.
type BatchEnforceResult struct {
	// Index is the zero-based position of the request in the input slice.
	Index int
	// Allowed is the enforcement decision. It is only meaningful when
	// Canceled is false and Err is nil.
	Allowed bool
	// Canceled reports whether the request was not decided because the
	// batch context was canceled or timed out.
	Canceled bool
	// Err holds the independent error of this request. A failing request
	// never changes the position or conclusion of the other requests.
	Err error
}

// BatchEnforceEx evaluates the requests concurrently, at most
// batchEnforceConcurrency at a time, and returns one independent result per
// request in the same order as the input. A single request error never aborts
// the batch, and canceled requests are reported as such instead of being
// treated as allow or deny.
func (e *Enforcer) BatchEnforceEx(ctx context.Context, requests [][]interface{}) ([]BatchEnforceResult, error) {
	return e.batchEnforce(ctx, "", requests)
}

// BatchEnforceExWithMatcher is BatchEnforceEx with a custom matcher applied to
// every request.
func (e *Enforcer) BatchEnforceExWithMatcher(ctx context.Context, matcher string, requests [][]interface{}) ([]BatchEnforceResult, error) {
	return e.batchEnforce(ctx, matcher, requests)
}

func (e *Enforcer) batchEnforce(ctx context.Context, matcher string, requests [][]interface{}) ([]BatchEnforceResult, error) {
	if ctx == nil {
		return nil, errors.New("batch enforce context is nil")
	}

	// The slice is allocated once and every slot is written exactly once at
	// its own index, so out-of-order completion cannot misalign results.
	results := make([]BatchEnforceResult, len(requests))

	jobs := make(chan int)
	var workers sync.WaitGroup

	workerCount := batchEnforceConcurrency
	if len(requests) < workerCount {
		workerCount = len(requests)
	}

	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				result := BatchEnforceResult{Index: index}

				if err := ctx.Err(); err != nil {
					result.Canceled = true
					result.Err = err
					results[index] = result
					continue
				}

				allowed, err := e.enforce(matcher, nil, requests[index]...)

				// Cancellation takes precedence over any outcome because
				// enforce itself is not context aware and the caller no
				// longer wants the decision.
				if ctxErr := ctx.Err(); ctxErr != nil {
					result.Canceled = true
					result.Err = ctxErr
					results[index] = result
					continue
				}

				result.Allowed = allowed
				result.Err = err
				results[index] = result
			}
		}()
	}

dispatch:
	for index := range requests {
		select {
		case <-ctx.Done():
			// Requests not handed to a worker yet have no independent
			// conclusion. Mark them explicitly as canceled instead of
			// leaving zero values that would look like a deny decision.
			for pending := index; pending < len(requests); pending++ {
				results[pending] = BatchEnforceResult{
					Index:    pending,
					Canceled: true,
					Err:      ctx.Err(),
				}
			}
			break dispatch
		case jobs <- index:
		}
	}
	close(jobs)
	workers.Wait()

	return results, nil
}
