/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package lb implement load balancer
package lb

import (
	"log"
	"os"

	"github.com/trustbloc/did-go/method/orb/util/concurrent/rollingcounter"
)

const (
	logPrefix = " [did-go/method/orb] "
)

var errorLogger = log.New(os.Stderr, logPrefix, log.Ldate|log.Ltime|log.LUTC)

// RoundRobin implements a round-robin load-balance policy.
type RoundRobin struct {
	counter *rollingcounter.Counter
}

// NewRoundRobin returns a new RoundRobin load-balance policy.
func NewRoundRobin() *RoundRobin {
	return &RoundRobin{
		counter: rollingcounter.New(),
	}
}

// Choose chooses from the list of domains in round-robin fashion.
func (rb *RoundRobin) Choose(domains []string) (string, error) {
	if len(domains) == 0 {
		errorLogger.Printf("No domains to choose from!")

		return "", nil
	}

	return domains[rb.counter.Next(len(domains))], nil
}
