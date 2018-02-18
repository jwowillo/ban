package ban

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// ipMapConstructor constructs an ipMap.
type ipMapConstructor func() ipMap

// testEmptyPrefix tests that an ipMap constructed by the ipMapConstructor
// correctly handles a prefix-length of 0 that includes every IP.
func testEmptyPrefix(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	m := c()
	pip, err := ParsePrefixedIP("::/0")
	if err != nil {
		t.Error(err)
	}
	m.Add(pip)
	for i := 0; i < n; i++ {
		ip := randomIP()
		if !m.Has(ip) {
			t.Errorf("m.Has(%v) = false, want true", ip)
		}
	}
}

// testPartialPrefix tests that an ipMap constructed by the ipMapConstructor
// correctly handles prefix-lengths that include some IPs.
func testPartialPrefix(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	m := c()
	pip1, err := ParsePrefixedIP("0.0.0.0/120")
	if err != nil {
		t.Error(err)
	}
	m.Add(pip1)
	pip2, err := ParsePrefixedIP("::/120")
	if err != nil {
		t.Error(err)
	}
	m.Add(pip2)
	for i := 0; i < 256; i++ {
		ip1, err := ParseIP(fmt.Sprintf("0.0.0.%d", i))
		if err != nil {
			t.Error(err)
		}
		if !m.Has(ip1) {
			t.Errorf("m.Has(%v) = false, want true", ip1)
		}
		ip2, err := ParseIP(fmt.Sprintf("::%x", i))
		if err != nil {
			t.Error(err)
		}
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
// correctly handles prefix-lengths that include only one IP.
func testFullPrefix(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	m := c()
	pip1, err := ParsePrefixedIP("255.255.255.255/128")
	if err != nil {
		t.Error(err)
	}
	pip2, err := ParsePrefixedIP("::/128")
	if err != nil {
		t.Error(err)
	}
	m.Add(pip1)
	m.Add(pip2)
	if !m.Has(pip1.IP()) {
		t.Errorf("m.Has(%v) = false, want true", pip1.IP())
	}
	if !m.Has(pip2.IP()) {
		t.Errorf("m.Has(%v) = false, want true", pip2.IP())
	}
	for i := 0; i < n; i++ {
		ip := randomIP()
		if isEqualIP(ip, pip1.IP()) || isEqualIP(ip, pip2.IP()) {
			continue
		}
		if m.Has(ip) {
			t.Errorf("m.Has(%v) = true, want false", ip)
		}
	}
}

// testIPv4IPv6Different tests that an ipMap constructed by the ipMapConstructor
// correctly handles IPv4 and IPv6 IPs that have the same byte values, either
// all 0 or all 0xFF.
func testIPv4IPv6Different(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	m1 := c()
	ipv4Zero, err := ParsePrefixedIP("0.0.0.0/128")
	if err != nil {
		t.Error(err)
	}
	ipv6Zero, err := ParsePrefixedIP("::/128")
	if err != nil {
		t.Error(err)
	}
	ipv4Full, err := ParsePrefixedIP("255.255.255.255/128")
	if err != nil {
		t.Error(err)
	}
	ipv6Full, err := ParsePrefixedIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
	if err != nil {
		t.Error(err)
	}
	m1.Add(ipv4Zero)
	m1.Add(ipv4Full)
	if m1.Has(ipv6Zero.IP()) {
		t.Errorf("m.Has(%v) = true, want false", ipv6Zero.IP())
	}
	if m1.Has(ipv6Full.IP()) {
		t.Errorf("m.Has(%v) = true, want false", ipv6Full.IP())
	}
	m2 := c()
	m2.Add(ipv6Zero)
	m2.Add(ipv6Full)
	if m2.Has(ipv4Zero.IP()) {
		t.Errorf("m.Has(%v) = true, want false", ipv4Zero.IP())
	}
	if m2.Has(ipv4Full.IP()) {
		t.Errorf("m.Has(%v) = true, want false", ipv4Full.IP())
	}
}

// testIPExists thats that an ipMap constructed by the ipMapConstructor handles
// the same IP being added more than once.
func testIPExists(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	ip := NewIPv4IP(IPv4{1, 2, 3, 4})
	pip, err := NewPrefixedIP(ip, ipLength)
	if err != nil {
		t.Error(err)
	}
	m := c()
	m.Add(pip)
	m.Add(pip)
	if !m.Has(pip.IP()) {
		t.Errorf("m.Has(%v) = false, want true", pip.IP())
	}
}

// testRandom tests that an ipMap constructed by the ipMapConstructor handles a
// sampling of random addresses with full prefix-lengths.
func testRandom(t *testing.T, c ipMapConstructor) {
	t.Parallel()
	const n = 100
	ips := make([]IP, n)
	for i := 0; i < n; i++ {
		ips[i] = randomIP()
	}
	m := c()
	for _, ip := range ips {
		pip, err := NewPrefixedIP(ip, 128)
		if err != nil {
			t.Error(err)
		}
		m.Add(pip)
	}
	for _, ip := range ips {
		if !m.Has(ip) {
			t.Errorf("m.Has(%v) = false, want true", ip)
		}
	}
}

// benchmarkAdd benchmarks Add of an ipMap constructed by the the
// ipMapConstructor.
func benchmarkAdd(b *testing.B, c ipMapConstructor) {
	const n = 10000
	ips := make([]*PrefixedIP, n)
	for i := range ips {
		pip, err := NewPrefixedIP(randomIP(), ipLength)
		if err != nil {
			b.Error(err)
		}
		ips[i] = pip
	}
	m := c()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Add(ips[i%len(ips)])
	}
}

// benchmarkHas benchmarks Has of an ipMap constructed by the ipMapConstructor.
func benchmarkHas(b *testing.B, c ipMapConstructor) {
	const n = 10000
	pips := make([]*PrefixedIP, n)
	ips := make([]IP, n)
	for i := range ips {
		pip, err := NewPrefixedIP(randomIP(), ipLength)
		if err != nil {
			b.Error(err)
		}
		pips[i] = pip
		ips[i] = pip.IP()
	}
	m := c()
	for _, ip := range pips {
		m.Add(ip)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Has(ips[i%len(ips)])
	}
}

// isEqualIP returns true if a and b are the same IP.
func isEqualIP(a, b IP) bool {
	return a == b
}

// randomIP returns a random IP which can be either IPv4 or IPv6.
func randomIP() IP {
	var ip IP
	if rand.Intn(2) == 0 {
		ip = ipv4Prefix
		for i := 12; i < ipv6Length; i++ {
			ip[i] = byte(rand.Uint32() % 0xFF)
		}
	} else {
		for i := range ip {
			ip[i] = byte(rand.Uint32() % 0xFF)
		}
	}
	return ip
}

// init seeds rand.
func init() {
	rand.Seed(time.Now().Unix())
}
