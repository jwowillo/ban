package ban

const (
	// bitsPerByte is the number of bits in a byte.
	bitsPerByte = 8
	// ipv4Length is the number of bytes in an IPv4 address.
	ipv4Length = 4
	// ipv6Length is the number of bytes in an IPv6 address.
	ipv6Length = 16
	// ipLength is the number of bits in an address which has been padded to
	// 16 bytes.
	ipLength = ipv6Length * bitsPerByte
)

// ipv4Prefix is the standard prefix prepended to IPv4 addresses to pad them to
// IPv6 length.
var ipv4Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}

// IP ...
type IP [ipv6Length]byte
