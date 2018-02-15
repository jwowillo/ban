package ban

import (
	"testing"
)

// trieConstructor returns a trie.
func trieConstructor() ipMap {
	return newTrie()
}

// TestEmptyPrefix calls testEmptyPrefix with trieConstructor.
func TestEmptyPrefix(t *testing.T) {
	testEmptyPrefix(t, trieConstructor)
}

// TestPartialPrefix calls testPartialPrefix with trieConstructor.
func TestPartialPrefix(t *testing.T) {
	testPartialPrefix(t, trieConstructor)
}

// TestFullPrefix calls testFullPrefix with trieConstructor.
func TestFullPrefix(t *testing.T) {
	testFullPrefix(t, trieConstructor)
}

// TestIPv4IPv6Different calls testIPv4IPv6Different with trieConstructor.
func TestIPv4IPv6Different(t *testing.T) {
	testIPv4IPv6Different(t, trieConstructor)
}

// TestRandom calls testRandom with trieConstructor.
func TestRandom(t *testing.T) {
	testRandom(t, trieConstructor)
}

// TestMalformed calls testMalformedAndBadPrefixLength with trieConstructor.
func TestMalformedAndBadPrefixLength(t *testing.T) {
	testMalformedAndBadPrefixLength(t, trieConstructor)
}

// BenchmarkAdd calls benchmarkAdd with trieConstructor.
func BenchmarkAdd(b *testing.B) {
	benchmarkAdd(b, trieConstructor)
}

// Benchmarkhas calls benchmarkHas with trieConstructor.
func BenchmarkHas(b *testing.B) {
	benchmarkHas(b, trieConstructor)
}
