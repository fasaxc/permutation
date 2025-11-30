package permutation

import (
	"fmt"
	"math/big"
	"testing"
)

func ExampleArbitraryN_PermuteInt() {
	const n = 5
	p := NewNInt([]byte("mykey"), n)
	for i := range n {
		fmt.Println(i, "->", p.PermuteInt(i))
	}
	// Output:
	// 0 -> 1
	// 1 -> 4
	// 2 -> 2
	// 3 -> 0
	// 4 -> 3
}

func TestPermute(t *testing.T) {
	for n := 1; n <= 1024; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			p := NewN([]byte("foo"), big.NewInt(int64(n)))
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

func TestPermuteVeryLarge(t *testing.T) {
	n := big.NewInt(1)
	n.Lsh(n, 150)
	p := NewN([]byte("foo"), n)
	seen := make(map[string]int)
	for i := 0; i < 100; i++ {
		out := p.PermuteInPlace(big.NewInt(int64(i)), nil)
		t.Log(i, "->", out)
		if n.Cmp(out) <= 0 {
			t.Fatalf("output %d is outside range of permutation [0, %v)", out, n)
		}
		if _, ok := seen[out.String()]; ok {
			t.Fatalf("found duplicate output %d", out)
		}
		seen[out.String()] = i
	}
}

func TestPowerOf2PermuteLength(t *testing.T) {
	for length := 2; length <= 18; length++ {
		t.Run(fmt.Sprintf("length %d", length), func(t *testing.T) {
			t.Parallel()
			t.Log("length", length)
			p := NewPowerOf2([]byte("foo"), length)
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

func TestFFXPermuteLength(t *testing.T) {
	for length := 8; length <= 18; length++ {
		t.Run(fmt.Sprintf("length %d", length), func(t *testing.T) {
			t.Parallel()
			t.Log("length", length)
			p := NewFFX([]byte("foo"), length)
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
	p1 := NewPowerOf2([]byte("foo"), length)
	p2 := NewPowerOf2([]byte("bar"), length)
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
	p := NewPowerOf2([]byte("foobarbaz"), 16)
	for b.Loop() {
		p.PermuteInt(1234)
	}
}

func BenchmarkFFX_PermuteInt(b *testing.B) {
	b.ReportAllocs()
	p := NewFFX([]byte("foobarbaz"), 16)
	for b.Loop() {
		p.PermuteInt(1234)
	}
}
