package ban

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

// Add the PrefixedIP to the trie.
func (m *trie) Add(pip *PrefixedIP) {
	ip := pip.IP()
	pl := pip.PrefixLength()
	current := m.root
	for i := byte(0); i < pl; i++ {
		child := (ip[i/bitsPerByte] >> (bitsPerByte - 1 - i%bitsPerByte)) & 1
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

// Has returns true if the IP matches a PrefixedIP stored in the trie.
func (m *trie) Has(ip IP) bool {
	current := m.root
	for i := byte(0); i < ipLength; i++ {
		if current.IsEnd {
			return true
		}
		child := (ip[i/bitsPerByte] >> (bitsPerByte - 1 - i%bitsPerByte)) & 1
		current = current.Children[child]
		if current == nil {
			break
		}
	}
	return current != nil && current.IsEnd
}
