package ban

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TODO: Go over code for docs and magic numbers.

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

// IP ...
type IP [ipv6Length]byte

// NewIPv4 ...
func NewIPv4(addr [4]byte) IP {
	ip := ipv4Prefix
	for i := 12; i < ipv6Length; i++ {
		ip[i] = addr[i-12]
	}
	return ip
}

// ipv4Prefix is the standard prefix prepended to IPv4 addresses to pad them to
// IPv6 length.
var ipv4Prefix = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}

// ParseIP ...
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

// PrefixedIP ...
type PrefixedIP struct {
	ip           IP
	prefixLength byte
}

var (
	// ErrBadIP ...
	ErrBadIP = errors.New("bad IP")
	// ErrBadPrefixedIP ...
	ErrBadPrefixedIP = errors.New("bad prefixed IP")
	// ErrInvalidPrefixLength ...
	ErrInvalidPrefixLength = errors.New(
		"prefix-length must be an integer less than or equal to 128",
	)
)

// NewPrefixedIP ...
func NewPrefixedIP(ip IP, pl byte) (*PrefixedIP, error) {
	if pl > ipLength {
		return nil, ErrInvalidPrefixLength
	}
	return &PrefixedIP{ip: ip, prefixLength: pl}, nil
}

// ParsePrefixedIP ...
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
		return nil, ErrInvalidPrefixLength
	}
	if pl > ipLength {
		return nil, ErrInvalidPrefixLength
	}
	return NewPrefixedIP(ip, byte(pl))
}

// IP ...
func (p *PrefixedIP) IP() IP {
	ip := p.ip
	for i := p.prefixLength; i < ipLength; i++ {
		ip[i/bitsPerByte] = ip[i/bitsPerByte] & ^(1 << (bitsPerByte - 1 - i%8))
	}
	return ip
}

// PrefixLength ...
func (p *PrefixedIP) PrefixLength() byte {
	return p.prefixLength
}

func (p *PrefixedIP) String() string {
	return fmt.Sprintf("%s/%d", p.IP(), p.prefixLength)
}
