package permutation

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math/big"
)

// FeistelSHAKE128 implements a variable-length block cipher to generate a key-dependent
// permutation over [0, 2^n - 1].  It uses a Feistel construction with SHAKE128 as the PRF
// for the round function.  This allows for arbitrarily-long inputs/outputs.
type FeistelSHAKE128 struct {
	key        []byte
	lengthBits int
	rounds     int

	// Scratch variables to avoid allocations.
	in, a, b, c, f, mask big.Int
	roundScratch         []byte

	h *sha3.SHAKE
}

func NewPowerOf2(key []byte, lengthBits int) *FeistelSHAKE128 {
	if lengthBits <= 1 {
		panic(fmt.Sprintf("lengthBits must be >1, got: %v", lengthBits))
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
	return &FeistelSHAKE128{
		key:        key,
		lengthBits: lengthBits,
		h:          sha3.NewSHAKE128(),
		rounds:     rounds,
	}
}

func (p *FeistelSHAKE128) PermuteInt(in int) int {
	return int(p.PermuteInPlace(p.in.SetInt64(int64(in)), nil).Int64())
}

// PermuteInPlace calculates inOut's permutated value and stores it back into inOut.
// Returns inOut as a convenience.
func (p *FeistelSHAKE128) PermuteInPlace(inOut *big.Int, tweak []byte) *big.Int {
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
		f = p.RoundFunc(i, b, f, tweak)
		c.Xor(a, f)
		a, b, c = b, c, a
	}
	out := inOut.Lsh(a, uint(split))
	out.Or(out, b)
	return out
}

func (p *FeistelSHAKE128) RoundFunc(round int, b, out *big.Int, tweak []byte) *big.Int {
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
	if len(tweak) > 0 {
		binary.LittleEndian.PutUint64(buf[:], uint64(len(tweak)))
		_, _ = h.Write(buf[:])
		_, _ = h.Write(tweak)
	}
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
