package ban

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

// ipMapConstructor constructs an ipMap.
type ipMapConstructor func() ipMap

// testEmptyPrefix tests that an ipMap constructed by the ipMapConstructor
// correctly handles a prefix-length of 0 that includes every address.
func testEmptyPrefix(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	m := c()
	m.Add(net.ParseIP("::0"), 0)
	for i := 0; i < n; i++ {
		ip := randomIP()
		if !m.Has(ip) {
			t.Errorf("m.Has(%v) = false, want true", ip)
		}
	}
}

// testPartialPrefix tests that an ipMap constructed by the ipMapConstructor
// correctly handles prefix-lengths that include some addresses.
func testPartialPrefix(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	m := c()
	m.Add(net.ParseIP("0.0.0.0"), 24)
	m.Add(net.ParseIP("::0"), 120)
	for i := 0; i < 256; i++ {
		ip1 := net.ParseIP(fmt.Sprintf("0.0.0.%d", i))
		if !m.Has(ip1) {
			t.Errorf("m.Has(%v) = false, want true", ip1)
		}
		ip2 := net.ParseIP(fmt.Sprintf("::%x", i))
		if !m.Has(ip2) {
			t.Errorf("m.Has(%v) = false, want true", ip2)
		}
	}
	for i := 0; i < n; i++ {
		ip := randomIP()
		allZero := true
		for i := 0; i < len(ip)-1; i++ {
			if ip[i] != 0 {
				allZero = false
			}
		}
		if allZero {
			continue
		}
		if m.Has(ip) {
			t.Errorf("m.Has(%v) = true, want false", ip)
		}
	}
}

// testFullPrefix tests that an ipMap constructed by the ipMapConstructor
// correctly handles prefix-lengths that include only one address.
func testFullPrefix(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	m := c()
	ip1 := net.ParseIP("255.255.255.255")
	ip2 := net.ParseIP("::0")
	m.Add(ip1, 32)
	m.Add(ip2, 128)
	if !m.Has(ip1) {
		t.Errorf("m.Has(%v) = false, want true", ip1)
	}
	if !m.Has(ip2) {
		t.Errorf("m.Has(%v) = false, want true", ip2)
	}
	for i := 0; i < n; i++ {
		ip := randomIP()
		if isEqualIP(ip, ip1) || isEqualIP(ip, ip2) {
			continue
		}
		if m.Has(ip) {
			t.Errorf("m.Has(%v) = true, want false", ip)
		}
	}
}

// testIPv4IPv6Different tests that an ipMap constructed by the ipMapConstructor
// correctly handles IPv4 and IPv6 addresses that have the same byte values,
// either all 0 or all 0xFF.
func testIPv4IPv6Different(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	m1 := c()
	ipv4Zero := net.ParseIP("0.0.0.0")
	ipv6Zero := net.ParseIP("::0")
	ipv4Full := net.ParseIP("255.255.255.255")
	ipv6Full := net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	m1.Add(ipv4Zero, 32)
	m1.Add(ipv4Full, 32)
	if m1.Has(ipv6Zero) {
		t.Errorf("m.Has(%v) = true, want false", ipv6Zero)
	}
	if m1.Has(ipv6Full) {
		t.Errorf("m.Has(%v) = true, want false", ipv6Full)
	}
	m2 := c()
	m2.Add(ipv6Zero, 128)
	m2.Add(ipv6Full, 128)
	if m2.Has(ipv4Zero) {
		t.Errorf("m.Has(%v) = true, want false", ipv4Zero)
	}
	if m2.Has(ipv4Full) {
		t.Errorf("m.Has(%v) = true, want false", ipv4Full)
	}
}

// testRandom tests that an ipMap constructed by the ipMapConstructor handles a
// sampling of random addresses with full prefix-lengths.
func testRandom(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	ips := make([]net.IP, n)
	for i := 0; i < n; i++ {
		ips[i] = randomIP()
	}
	m := c()
	for _, ip := range ips {
		m.Add(ip, byte(len(ip)*bitsPerByte))
	}
	for _, ip := range ips {
		if !m.Has(ip) {
			t.Errorf("m.Has(%v) = false, want true", ip)
		}
	}
}

// testMalformed tests that an ipMap constructed by the ipMapConstructor
// correctly handles malformed addresses and bad prefix-lengths.
func testMalformedAndBadPrefixLength(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	badIP := net.IP([]byte{0xFF})
	badPrefixLength := net.ParseIP("::1")
	m := c()
	m.Add(badIP, byte(len(badIP)*bitsPerByte))
	m.Add(badPrefixLength, byte(len(badPrefixLength)*bitsPerByte)+1)
	m.Add(nil, 0)
	if m.Has(badIP) {
		t.Errorf("m.Has(%v) = true, want false", badIP)
	}
	if m.Has(badPrefixLength) {
		t.Errorf("m.Has(%v) = true, want false", badPrefixLength)
	}
	if m.Has(nil) {
		t.Errorf("m.Has(%v) = true, want false", nil)
	}
}

// benchmarkAdd benchmarks Add of an ipMap constructed by the the
// ipMapConstructor.
func benchmarkAdd(b *testing.B, c ipMapConstructor) {
	const n = 10000
	ips := make([]net.IP, n)
	for i := range ips {
		ips[i] = randomIP()
	}
	m := c()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Add(ips[i%len(ips)], byte(len(ips)*bitsPerByte))
	}
}

// benchmarkHas benchmarks Has of an ipMap constructed by the ipMapConstructor.
func benchmarkHas(b *testing.B, c ipMapConstructor) {
	const n = 10000
	ips := make([]net.IP, n)
	for i := range ips {
		ips[i] = randomIP()
	}
	m := c()
	for _, ip := range ips {
		m.Add(ip, byte(len(ips)*bitsPerByte))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Has(ips[i%len(ips)])
	}
}

// isEqualIP returns true if a and b are the same net.IP.
func isEqualIP(a, b net.IP) bool {
	a = padTo16(a)
	b = padTo16(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// randomIP returns a random net.IP which can be either IPv4 or IPv6.
func randomIP() net.IP {
	var ip net.IP
	if rand.Intn(2) == 0 {
		ip = make([]byte, ipv4Length)
	} else {
		ip = make([]byte, ipv6Length)
	}
	for i := range ip {
		ip[i] = byte(rand.Uint32() % 0xFF)
	}
	return ip
}

// init seeds rand.
func init() {
	rand.Seed(time.Now().Unix())
}
