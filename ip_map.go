package ban

import (
	"errors"
	"net"
)

// bitsPerByte is the number of bits in a byte.
const bitsPerByte = 8

// ErrPrefixLength is returned if a prefix-Length too long is passed for an
// IP address.
var ErrPrefixLength = errors.New("invalid prefix-Length for IP")

// node in a trie.
//
// Stores the address legnth if the node marks an address end.
type node struct {
	Length   byte
	Children [2]*node
}

// ipMap is a trie which supports adding net.IPs and prefix lengths and checking
// for their presence efficiently.
type ipMap struct {
	root *node
}

// newIPMap creates an empty ipMap.
func newIPMap() *ipMap {
	return &ipMap{root: &node{}}
}

// Add the part of the net.IP specified by the prefix-length to the ipMap.
func (m *ipMap) Add(ip net.IP, prefixLength byte) error {
	ipLen := byte(len(ip)) * bitsPerByte
	if prefixLength > ipLen {
		return ErrPrefixLength
	}
	current := m.root
	for i := byte(0); i < prefixLength; i++ {
		child := bitAtIndex(ip, i)
		if current.Children[child] == nil {
			current.Children[child] = &node{}
		}
		current = current.Children[child]
		if current.Length != 0 {
			return nil
		}
	}
	current.Length = ipLen
	return nil
}

// Has returns true if the net.IP matches a net.IP and prefix-length stored in
// ipMap.
func (m *ipMap) Has(ip net.IP) bool {
	current := m.root
	ipLen := byte(len(ip)) * bitsPerByte
	for i := byte(0); i < ipLen; i++ {
		current = current.Children[bitAtIndex(ip, i)]
		if current == nil {
			break
		}
		if current.Length == ipLen {
			return true
		}
	}
	return false
}

// IPs returns all net.IP and prefix-length pairs stored in the ipMap.
func (m *ipMap) IPs() []ipPair {
	var out []ipPair
	findIPs(m.root, nil, &out)
	return out
}

// ipPair is a pair of a net.IP and a prefix-length.
type ipPair struct {
	IP           net.IP
	PrefixLength byte
}

// findIPs is a recursive helper function which finds all corresponding ipPairs
// from the passed node and stores them in out.
//
// path is meant to be initially passed as nil and is used to build the
// addresses.
func findIPs(n *node, path []byte, out *[]ipPair) {
	if n.Length != 0 {
		ip := make(net.IP, n.Length/bitsPerByte)
		for i := byte(0); i < n.Length; i++ {
			j := i / bitsPerByte
			ip[j] = ip[j] | path[i]<<(bitsPerByte-1-i%bitsPerByte)
		}
		*out = append(*out, ipPair{IP: ip, PrefixLength: n.Length})
		return
	}
	if n.Children[0] != nil {
		findIPs(n.Children[0], append(path, 0), out)
	}
	if n.Children[1] != nil {
		findIPs(n.Children[1], append(path, 1), out)
	}
}

// bitAtIndex returns the ith bit in the net.IP.
func bitAtIndex(ip net.IP, i byte) byte {
	return (ip[i/bitsPerByte] >> (bitsPerByte - 1 - i%bitsPerByte)) & 1
}
