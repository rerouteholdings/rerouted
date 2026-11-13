package api

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/rerouteholdings/rerouted/internal/chain"
)

// validChains remembers chains that validated, so sending to a group doesn't re-verify
// every member's whole chain several times per recipient.
//
// The key is a hash of the exact encoded entries, so a chain that changes in any way
// (an appended entry, a recovery fork, a move) is a different key and is validated
// afresh: nothing has to be invalidated, and concurrent writers can't make it stale.
// Validation depends only on the entries (chain.Validate reads no clock), so a cached
// state is what validating again would give.
var validChains = chainCache{m: map[[32]byte]*chain.State{}}

// maxCachedChains bounds the cache; when it's full it starts over.
const maxCachedChains = 8192

type chainCache struct {
	mu sync.Mutex
	m  map[[32]byte]*chain.State
}

// get returns a copy of the state for sum, or nil. Callers get their own copy, since
// some apply new entries to the state they're given.
func (c *chainCache) get(sum [32]byte) *chain.State {
	c.mu.Lock()
	st := c.m[sum]
	c.mu.Unlock()
	if st == nil {
		return nil
	}
	return st.Clone()
}

func (c *chainCache) put(sum [32]byte, st *chain.State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxCachedChains {
		clear(c.m)
	}
	c.m[sum] = st.Clone()
}

// chainSum hashes a chain's encoded entries, each prefixed with its length, so no two
// different lists of entries hash alike.
func chainSum(raw [][]byte) [32]byte {
	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(raw)))
	h.Write(n[:])
	for _, e := range raw {
		binary.BigEndian.PutUint64(n[:], uint64(len(e)))
		h.Write(n[:])
		h.Write(e)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return sum
}
