package ban

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	// bitsPerByte is the number of bits in a byte.
	bitsPerByte = 8
	// ipv4Length is the number of bytes in an IPv4 address.
	ipv4Length = 4
	// ipv6Length is the number of bytes in an IPv6 address.
	ipv6Length = 16
	// ipLength is the number of bits in an IP.
	ipLength = ipv6Length * bitsPerByte
)

var (
	// ErrBadIP is returned if a bad IP form is given.
	ErrBadIP = errors.New("bad IP")
	// ErrBadPrefixedIP is return if a bad PrefixedIP form is given.
	ErrBadPrefixedIP = errors.New("bad prefixed IP")
	// ErrBadPrefixLength is given if a bad prefix-length is given.
	ErrBadPrefixLength = errors.New("prefix-length must be an integer less than or equal to 128")
)

// IPv4 is a 4-byte IP.
type IPv4 [ipv4Length]byte

// IPv6 is a 6-byte IP.
type IPv6 [ipv6Length]byte

// IP address in standard 16-byte IPv6 form.
//
// IPv4 addresses have the prefix "::ffff" to pad them to 16 bytes.
type IP IPv6

// ipv4Prefix is the standard prefix prepended to IPv4 addresses to pad them to
// IP length.
var ipv4Prefix = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

// NewIPv4IP creates an IP with the given IPv4 bytes appended to the
// IPv4-prefix.
func NewIPv4IP(addr IPv4) IP {
	ip := ipv4Prefix
	for i := (ipv6Length - ipv4Length); i < ipv6Length; i++ {
		ip[i] = addr[i-(ipv6Length-ipv4Length)]
	}
	return ip
}

// ParseIP from the string form of the IPv4 or IPv6 address.
//
// Returns an error if an IP couldn't be parsed from the string.
func ParseIP(sip string) (IP, error) {
	nip := net.ParseIP(sip)
	if nip == nil {
		return IP{}, ErrBadIP
	}
	ip := ipv4Prefix
	for i := len(ip) - 1; i >= len(ip)-len(nip); i-- {
		ip[i] = nip[i-(len(ip)-len(nip))]
	}
	return ip, nil
}

func (ip IP) String() string {
	return net.IP(ip[:]).String()
}

// PrefixedIP is an IP with a prefix-length that determines the amount of
// relevant bits in the address.
type PrefixedIP struct {
	ip           IP
	prefixLength byte
}

// NewPrefixedIP where the relevant bits from the IP are included.
//
// The prefix-length must be greater than or equal to 0 and less than or equal
// to 128, since that is the number of bits in an IP.
//
// Returns an error if an invalid prefix-length is given.
func NewPrefixedIP(ip IP, pl byte) (*PrefixedIP, error) {
	if pl > ipLength {
		return nil, ErrBadPrefixLength
	}
	return &PrefixedIP{ip: ip, prefixLength: pl}, nil
}

// ParsePrefixedIP from the string form of the IPv4 or IPv6 address with prefix
// appended after a slash.
//
// Returns an erorr if a PrefixedIP couldn't be parsed from the string.
func ParsePrefixedIP(pip string) (*PrefixedIP, error) {
	split := strings.Split(pip, "/")
	if len(split) != 2 {
		return nil, ErrBadPrefixedIP
	}
	ip, err := ParseIP(split[0])
	if err != nil {
		return nil, err
	}
	pl, err := strconv.Atoi(split[1])
	if err != nil {
		return nil, ErrBadPrefixLength
	}
	if pl < 0 || pl > ipLength {
		return nil, ErrBadPrefixLength
	}
	return NewPrefixedIP(ip, byte(pl))
}

// IP with all bits with all bits after the prefix masked.
func (p *PrefixedIP) IP() IP {
	ip := p.ip
	for i := p.prefixLength; i < ipLength; i++ {
		ip[i/bitsPerByte] = ip[i/bitsPerByte] & ^(1 << (bitsPerByte - 1 - i%bitsPerByte))
	}
	return ip
}

// PrefixLength is the number of bits in the PrefixedIP that matter.
func (p *PrefixedIP) PrefixLength() byte {
	return p.prefixLength
}

func (p *PrefixedIP) String() string {
	return fmt.Sprintf("%s/%d", p.IP(), p.prefixLength)
}
