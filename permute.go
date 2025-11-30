package permutation

import (
	"fmt"
	"math/big"
)

type Permutation interface {
	PermuteInt(in int) int
	PermuteInPlace(inOut *big.Int, tweak []byte) *big.Int
}

// ArbitraryN builds on one of the block permutations to make a permutation over an arbitrary range.
// The underlying power-of-2 permutation is iterated to find an in-range result resulting
// in variable runtime.
type ArbitraryN struct {
	p     Permutation
	n, in big.Int
}

func NewNInt(key []byte, n int) *ArbitraryN {
	return NewN(key, big.NewInt(int64(n)))
}

func NewN(key []byte, n *big.Int) *ArbitraryN {
	var nMinus1 big.Int
	nMinus1.Sub(n, big.NewInt(1))
	bitLen := nMinus1.BitLen()
	if bitLen <= 1 {
		// Feistel network requires at least 2 bits.
		bitLen = 2
	}
	var p2n Permutation
	if bitLen >= 8 && bitLen <= 128 {
		// Faster but only supports certain ranges.
		p2n = NewFFX(key, bitLen)
	} else {
		p2n = NewPowerOf2(key, bitLen)
	}
	p := &ArbitraryN{
		p: p2n,
	}
	p.n.Set(n)
	return p
}

func (p *ArbitraryN) PermuteInt(in int) int {
	return int(p.PermuteInPlace(p.in.SetInt64(int64(in)), nil).Int64())
}

// PermuteInPlace calculates inOut's permutated value and stores it back into inOut.
// Returns inOut as a convenience.
func (p *ArbitraryN) PermuteInPlace(inOut *big.Int, tweak []byte) *big.Int {
	if inOut.Cmp(&p.n) >= 0 {
		panic(fmt.Sprintf("input %v is outside range of permutation [0, %v)",
			inOut, p.n))
	}

	// Iterate the underlying 2^n permutation until we find an in-range value. This is
	// guaranteed to terminate because iterating a permutation must form a cycle.  If we're
	// unlucky and the cycle is short we'll get back to the same value.
	for {
		inOut = p.p.PermuteInPlace(inOut, tweak)
		if inOut.Cmp(&p.n) < 0 {
			return inOut
		}
	}
}
