package ban

import (
	"errors"
	"net"
)

// TODO: When all of the bit choices at a level are banned, mark the parent as
// the end and delete the children. This can help optimize space complexity
// further. Extend this to the saved ban list by rewriting with the proper
// prefix lengths.
// TODO: Add mutexes

const bitsPerByte = 8

// ErrPrefixLength ...
var ErrPrefixLength = errors.New("invalid prefix-length for IP")

type node struct {
	length   byte
	children [2]*node
}

type ipMap struct {
	root *node
}

func newIPMap() *ipMap {
	return &ipMap{root: &node{}}
}

func (m *ipMap) Add(ip net.IP, prefixLength byte) error {
	ipLen := byte(len(ip)) * bitsPerByte
	if prefixLength > ipLen {
		return ErrPrefixLength
	}
	current := m.root
	for i := byte(0); i < prefixLength; i++ {
		child := bitAtIndex(ip, i)
		if current.children[child] == nil {
			current.children[child] = &node{}
		}
		current = current.children[child]
		if current.length != 0 {
			return nil
		}
	}
	current.length = ipLen
	return nil
}

func (m *ipMap) Has(ip net.IP) bool {
	current := m.root
	ipLen := byte(len(ip)) * bitsPerByte
	for i := byte(0); i < ipLen; i++ {
		current = current.children[bitAtIndex(ip, i)]
		if current == nil {
			break
		}
		if current.length == ipLen {
			return true
		}
	}
	return false
}

type ipPair struct {
	IP           net.IP
	PrefixLength byte
}

func (m *ipMap) IPs() []ipPair {
	var out []ipPair
	findIPs(m.root, nil, &out)
	return out
}

func findIPs(n *node, path []byte, out *[]ipPair) {
	if n.length != 0 {
		ip := make(net.IP, n.length/bitsPerByte)
		for i := byte(0); i < n.length; i++ {
			j := i / bitsPerByte
			ip[j] = ip[j] | path[i]<<(bitsPerByte-1-i%bitsPerByte)
		}
		*out = append(*out, ipPair{IP: ip, PrefixLength: n.length})
		return
	}
	if n.children[0] != nil {
		findIPs(n.children[0], append(path, 0), out)
	}
	if n.children[1] != nil {
		findIPs(n.children[1], append(path, 1), out)
	}
}

func bitAtIndex(ip net.IP, i byte) byte {
	return (ip[i/bitsPerByte] >> (bitsPerByte - 1 - i%bitsPerByte)) & 1
}
