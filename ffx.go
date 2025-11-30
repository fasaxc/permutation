package permutation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"
)

// FFX implements a permutation over [0, 2^lengthBits) using the FFX-A2 construction over AES. Key derivation
// uses HKDF, so the input key can be any length. Where needed, numbers are encoded in big-endian.
type FFX struct {
	lengthBits int
	rounds     int

	// Pre-calculated values.
	tweakLen      int
	mask          *big.Int
	p, encryptedP [aes.BlockSize]byte
	q             []byte

	// Scratch variables to avoid allocations.
	in, masked        big.Int
	inBytes, outBytes [aes.BlockSize]byte

	aes cipher.Block
}

func NewFFX(key []byte, lengthBits int) *FFX {
	if lengthBits < 8 || lengthBits > 128 {
		panic(fmt.Sprintf("lengthBits must be in [8, 128], got: %v", lengthBits))
	}

	aesKey, err := hkdf.Key(sha256.New, key, nil, "permute.FFX", 16)
	if err != nil {
		panic(err)
	}
	a, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
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

	// Calculate mask for extracting B from the input.  The input is treated as a big-endian 0-padded bit sequence
	// A || B.  We want B to end up with the larger split when the length is odd.
	mask := big.NewInt(1)
	split := lengthBits / 2
	mask = mask.Lsh(mask, uint(lengthBits-split))
	mask = mask.Sub(mask, big.NewInt(1))

	p := &FFX{
		lengthBits: lengthBits,
		aes:        a,
		rounds:     rounds,
		mask:       mask,
		tweakLen:   -1,
	}

	const (
		vers     = 1
		method   = 2 // Alternating Feistel
		addition = 0 // Characterwise addition
		radix    = 2
	)

	P := p.p[:]
	binary.BigEndian.PutUint16(P[0:2], vers)
	P[2] = method
	P[3] = addition
	P[4] = byte(radix)
	P[5] = byte(p.lengthBits)
	P[6] = byte(split)
	P[7] = byte(p.rounds)

	return p
}

func (p *FFX) PermuteInt(in int) int {
	p.in.SetInt64(int64(in))
	out := int(p.PermuteInPlace(&p.in, nil).Int64())
	p.in.SetUint64(0)
	return out
}

// PermuteInPlace calculates inOut's permutated value and stores it back into inOut.
// Returns inOut as a convenience.
func (p *FFX) PermuteInPlace(inOut *big.Int, tweak []byte) *big.Int {
	split := p.lengthBits / 2

	p.masked.And(inOut, p.mask)
	b := p.masked.Uint64()
	p.masked.Rsh(inOut, uint(p.lengthBits-split))
	a := p.masked.Uint64()

	p.calculateEncryptedP(split, len(tweak))

	p.q = append(p.q[:0], tweak...)
	for len(p.q)%16 != 7 {
		p.q = append(p.q, 0)
	}
	p.q = append(p.q, 1)
	for range 8 {
		p.q = append(p.q, 0)
	}

	var c uint64
	for i := range p.rounds {
		c = a ^ p.RoundFunc(i, b, nil)
		a = b
		b = c
	}

	inOut.SetUint64(a)
	inOut.Lsh(inOut, uint(p.lengthBits-split))
	p.masked.SetUint64(b)
	inOut.Or(inOut, &p.masked)
	p.masked.SetUint64(0)
	return inOut
}

func (p *FFX) calculateEncryptedP(split int, tweakLen int) {
	if tweakLen == p.tweakLen {
		return // already calculated.
	}
	binary.BigEndian.PutUint64(p.p[8:16], uint64(tweakLen))
	p.aes.Encrypt(p.encryptedP[:], p.p[:])
	p.tweakLen = tweakLen
}

func (p *FFX) RoundFunc(i int, B uint64, tweak []byte) uint64 {
	split := p.lengthBits / 2

	binary.BigEndian.PutUint64(p.q[len(p.q)-8:], B)

	// CBC-MAC
	inBytes := p.inBytes[:]
	outBytes := p.outBytes[:]
	copy(outBytes, p.encryptedP[:])
	remainingQ := p.q[:]
	for len(remainingQ) > 0 {
		block := remainingQ[:aes.BlockSize]
		remainingQ = remainingQ[aes.BlockSize:]
		subtle.XORBytes(inBytes, outBytes, block)
		p.aes.Encrypt(outBytes, inBytes)
	}

	out := binary.BigEndian.Uint64(outBytes[8:16])
	var bitsToKeep int
	if i&1 == 0 {
		bitsToKeep = split
	} else {
		bitsToKeep = p.lengthBits - split
	}
	bitsToLose := 64 - bitsToKeep
	out = (out << bitsToLose) >> bitsToLose
	return out
}
