package ban

import (
	"net"
)

// node in a trie.
type node struct {
	// IsEnd is true if this node is the last relevant node in the search
	// for an address.
	IsEnd bool
	// Children is the next bit in the address read from left to right.
	Children [2]*node
}

// trie is a trie which supports adding net.IPs and prefix-lengths and checking
// for their presence efficiently.
type trie struct {
	root *node
}

// newTrie creates an empty trie.
func newTrie() *trie {
	return &trie{root: &node{}}
}

// Add the part of the net.IP specified by the prefix-length to the trie.
//
// The prefix-length should be in terms of a 16-byte address.
//
// Malformed or nil addresses and invalid prefix-lengths are ignored.
func (m *trie) Add(ip net.IP, prefixLength byte) {
	if ip == nil || len(ip) != ipv6Length {
		return
	}
	if prefixLength > ipLength {
		return
	}
	current := m.root
	for i := byte(0); i < prefixLength; i++ {
		child := bitAtIndex(ip, i)
		if current.Children[child] == nil {
			current.Children[child] = &node{}
		}
		current = current.Children[child]
		if current.IsEnd {
			return
		}
	}
	current.IsEnd = true
}

// Has returns true if the net.IP matches a net.IP and prefix-length stored in
// the trie.
//
// False is returned if the address is malformed or nil.
func (m *trie) Has(ip net.IP) bool {
	if ip == nil || len(ip) != ipv6Length {
		return false
	}
	current := m.root
	for i := byte(0); i < ipLength; i++ {
		if current.IsEnd {
			return true
		}
		current = current.Children[bitAtIndex(ip, i)]
		if current == nil {
			break
		}
	}
	return current != nil && current.IsEnd
}

// bitAtIndex returns the ith bit in the net.IP.
func bitAtIndex(ip net.IP, i byte) byte {
	return (ip[i/bitsPerByte] >> (bitsPerByte - 1 - i%bitsPerByte)) & 1
}
