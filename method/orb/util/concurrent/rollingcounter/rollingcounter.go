/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package rollingcounter implement rolling counter
package rollingcounter

import (
	"crypto/rand"
	"io"
	"log"
	"math/big"
	"sync/atomic"
)

var debugLogger = log.New(io.Discard, " [did-go/method/orb] ", log.Ldate|log.Ltime|log.LUTC)

// SetDebugOutput is used to set output of debug logs.
func SetDebugOutput(out io.Writer) {
	debugLogger.SetOutput(out)
}

// Counter is a rolling counter that increments an index up to a maximum value. If the counter reaches
// the maximum then the counter resets to 0. A single counter instance may be used by multiple Go routines.
type Counter struct {
	index int32
}

// New returns a new rolling counter.
func New() *Counter {
	return &Counter{index: -1}
}

// Next increments the counter. If the counter reaches n then
// the counter is reset to 0. Note: n must be greater than 0 or else
// a panic will result.
func (c *Counter) Next(n int) int {
	if n <= 0 {
		panic("n must be greater than 0")
	}

	for {
		current := atomic.LoadInt32(&c.index)
		debugLogger.Printf("Current index: %d", current)

		i := int(current)
		if i == -1 {
			// Choose a random index the first time
			result, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
			if err != nil {
				panic(err.Error())
			}

			i = int(result.Int64())
		} else {
			i++
			if i >= n {
				i = 0
			}
		}

		if atomic.CompareAndSwapInt32(&c.index, current, int32(i)) {
			debugLogger.Printf("Set the counter to %d", i)

			return i
		}

		debugLogger.Printf("Another thread has already incremented the counter. Trying again...")
	}
}
