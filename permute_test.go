package permute

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPermute(t *testing.T) {
	for n := 1; n <= 1024; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			p := NewPermutationN([]byte("foo"), big.NewInt(int64(n)))
			seen := make(map[int]int)
			for i := 0; i < n; i++ {
				out := p.PermuteInt(i)
				if out >= n {
					t.Fatalf("output %d is outside range of permutation [0, %d)", out, n)
				}
				if _, ok := seen[out]; ok {
					t.Fatalf("found duplicate output %d", out)
				}
				seen[out] = i
			}
		})
	}
}

func TestPermuteLength(t *testing.T) {
	for length := 1; length <= 18; length++ {
		t.Run(fmt.Sprintf("length %d", length), func(t *testing.T) {
			t.Parallel()
			t.Log("length", length)
			p := NewPermutationPowerOf2([]byte("foo"), length)
			seen := make(map[int]int)
			for i := 0; i < (1 << length); i++ {
				out := p.PermuteInt(i)
				if other, ok := seen[out]; ok {
					t.Fatalf("Found duplicate (length %d) permute %d, %d -> %d", length, i, other, out)
				}
				seen[out] = i
			}
		})
	}
}

func TestPermuteKey(t *testing.T) {
	const length = 16
	t.Log("length", length)
	p1 := NewPermutationPowerOf2([]byte("foo"), length)
	p2 := NewPermutationPowerOf2([]byte("bar"), length)
	numCollisions := 0
	for i := 0; i < (1 << length); i++ {
		if p1.PermuteInt(i) == p2.PermuteInt(i) {
			numCollisions++
			t.Log("collision", i, "->", p2.PermuteInt(i))
		}
	}
	t.Log("NumCollisions", numCollisions)
	if numCollisions > 10 {
		t.Fatal("Too many collisions")
	}
}

func BenchmarkPermutation_PermuteInt(b *testing.B) {
	b.ReportAllocs()
	p := NewPermutationPowerOf2([]byte("foobarbaz"), 16)
	for b.Loop() {
		p.PermuteInt(1234)
	}
}
