# github.com/fasaxc/permutation

Library for generating key-dependent permutations of (potentially big) integers.

Example [go playground](https://go.dev/play/p/QlDCnx8VcfH):
```go
package main

import (
	"fmt"

	"github.com/fasaxc/permutation"
)

func main() {
	const n = 5
	p := permutation.NewNInt([]byte("mykey"), n)
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
```