package permute

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math/big"
)

// ArbitraryN builds on PowerOf2 to make a permutation over an arbitrary range.
// The underlying power-of-2 permutation is iterated to find an in-range result resulting
// in variable runtime.
type ArbitraryN struct {
	p     *PowerOf2
	n, in big.Int
}

func NewN(key []byte, n *big.Int) *ArbitraryN {
	var nMinus1 big.Int
	nMinus1.Sub(n, big.NewInt(1))
	bitLen := nMinus1.BitLen()
	if bitLen <= 1 {
		// Feistel network requires at least 2 bits.
		bitLen = 2
	}
	p2n := NewPowerOf2(key, bitLen)
	p := &ArbitraryN{
		p: p2n,
	}
	p.n.Set(n)
	return p
}

func (p *ArbitraryN) PermuteInt(in int) int {
	return int(p.PermuteInPlace(p.in.SetInt64(int64(in))).Int64())
}

// PermuteInPlace calculates inOut's permutated value and stores it back into inOut.
// Returns inOut as a convenience.
func (p *ArbitraryN) PermuteInPlace(inOut *big.Int) *big.Int {
	if inOut.Cmp(&p.n) >= 0 {
		panic(fmt.Sprintf("input %v is outside range of permutation [0, %v)",
			inOut, p.n))
	}

	// Iterate the underlying 2^n permutation until we find an in-range value. This is
	// guaranteed to terminate because iterating a permutation must form a cycle.  If we're
	// unlucky and the cycle is short we'll get back to the same value.
	for {
		inOut = p.p.PermuteInPlace(inOut)
		if inOut.Cmp(&p.n) < 0 {
			return inOut
		}
	}
}

// PowerOf2 implements a variable-length block cipher to generate a key-dependent
// permutation over [0, 2^n - 1].  It uses a Feistel construction with SHAKE128 as the PRF
// for the round function.
type PowerOf2 struct {
	key        []byte
	lengthBits int
	rounds     int

	// Scratch variables to avoid allocations.
	in, a, b, c, f, mask big.Int
	roundScratch         []byte

	h *sha3.SHAKE
}

func NewPowerOf2(key []byte, lengthBits int) *PowerOf2 {
	if lengthBits <= 1 {
		panic("lengthBits must be >1")
	}
	var rounds int
	if lengthBits <= 9 {
		rounds = 36
	} else if lengthBits <= 13 {
		rounds = 30
	} else if lengthBits <= 19 {
		rounds = 24
	} else if lengthBits <= 31 {
		rounds = 18
	} else {
		rounds = 12
	}
	return &PowerOf2{
		key:        key,
		lengthBits: lengthBits,
		h:          sha3.NewSHAKE128(),
		rounds:     rounds,
	}
}

func (p *PowerOf2) PermuteInt(in int) int {
	return int(p.PermuteInPlace(p.in.SetInt64(int64(in))).Int64())
}

// PermuteInPlace calculates inOut's permutated value and stores it back into inOut.
// Returns inOut as a convenience.
func (p *PowerOf2) PermuteInPlace(inOut *big.Int) *big.Int {
	split := p.lengthBits / 2
	mask := &p.mask
	mask.SetInt64(1)
	mask.Lsh(mask, uint(split))
	mask.Sub(mask, big.NewInt(1))
	a := &p.a
	b := &p.b
	c := &p.c
	f := &p.f
	b.And(inOut, mask)
	a.Rsh(inOut, uint(split))
	for i := range p.rounds {
		f = p.RoundFunc(i, b, f)
		c.Xor(a, f)
		a, b, c = b, c, a
	}
	out := inOut.Lsh(a, uint(split))
	out.Or(out, b)
	return out
}

func (p *PowerOf2) RoundFunc(round int, b, out *big.Int) *big.Int {
	var inLenBits, outLenBits int
	if round&1 == 0 {
		inLenBits = p.lengthBits / 2
		outLenBits = p.lengthBits - inLenBits
	} else {
		outLenBits = p.lengthBits / 2
		inLenBits = p.lengthBits - outLenBits
	}

	if len(p.roundScratch) < (p.lengthBits+7)/8 {
		p.roundScratch = make([]byte, (p.lengthBits+7)/8)
	}
	h := p.h
	h.Reset()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(p.key)))
	_, _ = h.Write(buf[:])
	_, _ = h.Write(p.key)
	binary.LittleEndian.PutUint64(buf[:], uint64(outLenBits))
	_, _ = h.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(round))
	_, _ = h.Write(buf[:])

	inLenBytes := (inLenBits + 7) / 8
	scratch := p.roundScratch[:inLenBytes]
	b.FillBytes(scratch)
	_, _ = h.Write(scratch)

	outLenBytes := (outLenBits + 7) / 8
	outBytes := p.roundScratch[:outLenBytes]
	_, _ = h.Read(outBytes)
	rem := outLenBits % 8
	if rem != 0 {
		mask := 0xff >> (8 - rem)
		outBytes[0] = outBytes[0] & byte(mask)
	}
	out.SetBytes(outBytes)
	return out
}
