package ban

import (
	"testing"
)

// TestNewIPv4IP tests that the NewIPv4IP constructor correctly prefixes IPv4s
// into IPs.
func TestNewIPv4IP(t *testing.T) {
	t.Parallel()
	ipv4 := IPv4{1, 1, 1, 1}
	ip1 := NewIPv4IP(ipv4)
	ip2 := IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 1, 1, 1}
	if ip1 != ip2 {
		t.Errorf("NewIPv4IP(%v) = %v, want %v", ipv4, ip1, ip2)
	}
}

// TestParseIP tests that ParseIP correctly parses string IP representations
// into IPs.
func TestParseIP(t *testing.T) {
	t.Parallel()
	goodIP := IP{17, 17, 0, 0, 17, 17, 0, 0, 0, 0, 17, 17, 17, 17, 17, 17}
	goods := []struct {
		String string
		IP     IP
	}{
		{String: "1.2.3.4", IP: NewIPv4IP(IPv4{1, 2, 3, 4})},
		{String: "::", IP: IP{}},
		{String: "::1", IP: IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{String: "1111:0000:1111:0000:0000:1111:1111:1111", IP: goodIP},
		{String: "1111:0:1111:0000:0000:1111:1111:1111", IP: goodIP},
		{String: "1111:0000:1111::1111:1111:1111", IP: goodIP},
		{String: "1111:0:1111::1111:1111:1111", IP: goodIP},
	}
	for _, good := range goods {
		ip, err := ParseIP(good.String)
		if err != nil {
			t.Error(err)
		}
		if ip != good.IP {
			t.Errorf("ParseIP(%v) = %v, want %v", good.String, ip, good.IP)
		}
	}
	bads := []string{"", "1111::1111::", "0:0", "g:g:g:g:g:g:g:g", "a.b.c.d"}
	for _, bad := range bads {
		ip, err := ParseIP(bad)
		if err != ErrBadIP {
			t.Errorf("ParseIP(%v) = %v, want ErrBadIP", bad, ip)
		}
	}
}

// TestIPString tests that IPs are correctly converted to strings.
func TestIPString(t *testing.T) {
	t.Parallel()
	ips := []struct {
		IP     IP
		String string
	}{
		{IP: IP{}, String: "::"},
		{IP: IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, String: "::1"},
		{IP: IP{1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, String: "101::101:101:101:0:0"},
		{IP: NewIPv4IP(IPv4{0, 0, 0, 0}), String: "0.0.0.0"},
		{IP: NewIPv4IP(IPv4{1, 2, 3, 4}), String: "1.2.3.4"},
	}
	for _, ip := range ips {
		if ip.IP.String() != ip.String {
			t.Errorf(
				"ip.String() = %v, want %v",
				ip.IP.String(),
				ip.String,
			)
		}
	}
}

// TestPrefixedIP tests that PrefixedIPs are properly constructed and return the
// right IP and PrefixLength.
func TestPrefixedIP(t *testing.T) {
	t.Parallel()
	ip := IP{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := byte(0); i <= ipLength; i++ {
		pip, err := NewPrefixedIP(ip, i)
		if err != nil {
			t.Errorf("NewPrefixedIP(%v, %d) = %s, want nil", ip, i)
		}
		mip := pip.IP()
		for j := i + 1; j < byte(ipLength); j++ {
			bit := mip[j/bitsPerByte] & (1 << (bitsPerByte - 1 - j%bitsPerByte))
			if bit != 0 {
				t.Errorf("bit after prefix isn't 0")
			}
		}
		if pip.PrefixLength() != i {
			t.Errorf(
				"pip.PrefixLength() = %d, want %d",
				pip.PrefixLength(), i,
			)
		}
	}
	for i := ipLength + 1; i <= ipLength*2-1; i++ {
		// i isn't casted to a byte to prevent overflow.
		_, err := NewPrefixedIP(ip, byte(i))
		if err != ErrBadPrefixLength {
			t.Errorf(
				"NewPrefixedIP(%v, %d) = %v, want %v",
				err, ErrBadPrefixLength,
			)
		}
	}
}

// parsePrefixedIPCase is a case involving a PrefixedIP.
type parsePrefixedIPCase struct {
	PrefixedIP *PrefixedIP
	String     string
}

// parsePrefixedIPErrorCase is a case involving a PrefixedIP and error.
type parsePrefixedIPErrorCase struct {
	String string
	Error  error
}

// TestParseIP tests that ParsePrefixedIP correctly parses string PrefixedIP
// representations into PrefixedIPs.
func TestParsePrefixedIP(t *testing.T) {
	t.Parallel()
	goods := []parsePrefixedIPCase{}
	pip1, err := NewPrefixedIP(IP{}, 0)
	if err != nil {
		t.Error(err)
	}
	goods = append(goods, parsePrefixedIPCase{PrefixedIP: pip1, String: "::/0"})
	pip2, err := NewPrefixedIP(IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128)
	if err != nil {
		t.Error(err)
	}
	goods = append(goods, parsePrefixedIPCase{PrefixedIP: pip2, String: "::1/128"})
	pip3, err := NewPrefixedIP(IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 127)
	if err != nil {
		t.Error(err)
	}
	goods = append(goods, parsePrefixedIPCase{PrefixedIP: pip3, String: "::1/127"})
	pip4, err := NewPrefixedIP(NewIPv4IP(IPv4{1, 2, 3, 4}), 128)
	if err != nil {
		t.Error(err)
	}
	goods = append(goods, parsePrefixedIPCase{PrefixedIP: pip4, String: "1.2.3.4/128"})
	for _, good := range goods {
		pip, err := ParsePrefixedIP(good.String)
		if err != nil {
			t.Error(err)
		}
		if good.PrefixedIP.IP() != pip.IP() {
			t.Errorf(
				"ParsePrefixedIP(%v).IP() = %v, want %v",
				good.String, pip.IP(), good.PrefixedIP.IP(),
			)
		}
		if good.PrefixedIP.PrefixLength() != pip.PrefixLength() {
			t.Errorf(
				"ParsePrefixedIP(%v).PrefixLength() = %d, want %d",
				good.String, pip.PrefixLength(), good.PrefixedIP.PrefixLength(),
			)
		}
	}
	bads := []parsePrefixedIPErrorCase{
		{String: "1.2.3.4", Error: ErrBadPrefixedIP},
		{String: "1.2.3.4/0/0", Error: ErrBadPrefixedIP},
		{String: "1.2.3.4/a", Error: ErrBadPrefixLength},
		{String: "1.2.3.4/-256", Error: ErrBadPrefixLength},
		{String: "1.2.3.4/129", Error: ErrBadPrefixLength},
		{String: "1.2.3.a/128", Error: ErrBadIP},
		{String: "1111::1111::/128", Error: ErrBadIP},
	}
	for _, bad := range bads {
		_, err := ParsePrefixedIP(bad.String)
		if err != bad.Error {
			t.Errorf(
				"ParsePrefixedIP(%v) = %v, want %v",
				bad.String, err, bad.Error,
			)
		}
	}
}

// TestPrefixedIPString tests that PrefixedIPs are correctly converted to
// strings.
func TestPrefixedIPString(t *testing.T) {
	t.Parallel()
	pips := []parsePrefixedIPCase{}
	pip1, err := NewPrefixedIP(IP{}, 128)
	if err != nil {
		t.Error(err)
	}
	pips = append(pips, parsePrefixedIPCase{PrefixedIP: pip1, String: "::/128"})
	pip2, err := NewPrefixedIP(IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 127)
	if err != nil {
		t.Error(err)
	}
	pips = append(pips, parsePrefixedIPCase{PrefixedIP: pip2, String: "::/127"})
	pip3, err := NewPrefixedIP(IP{1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0}, 120)
	if err != nil {
		t.Error(err)
	}
	pips = append(pips, parsePrefixedIPCase{PrefixedIP: pip3, String: "101::101:101:101:0:0/120"})
	pip4, err := NewPrefixedIP(NewIPv4IP(IPv4{0, 0, 0, 0}), 96)
	if err != nil {
		t.Error(err)
	}
	pips = append(pips, parsePrefixedIPCase{PrefixedIP: pip4, String: "0.0.0.0/96"})
	pip5, err := NewPrefixedIP(NewIPv4IP(IPv4{1, 2, 3, 4}), 128)
	if err != nil {
		t.Error(err)
	}
	pips = append(pips, parsePrefixedIPCase{PrefixedIP: pip5, String: "1.2.3.4/128"})
	for _, pip := range pips {
		if pip.PrefixedIP.String() != pip.String {
			t.Errorf(
				"pip.String() = %v, want %v",
				pip.PrefixedIP.String(), pip.String,
			)
		}
	}
}
