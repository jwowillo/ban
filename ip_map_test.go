package ban

import (
	"net"
	"testing"
)

func BenchmarkIPMapAdd(b *testing.B) {
	m := newIPMap()
	ip := net.ParseIP("168.192.0.0").To4()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Add(ip, 32)
	}
}

func BenchmarkIPMapHas(b *testing.B) {
	m := newIPMap()
	ip := net.ParseIP("168.192.0.0").To4()
	m.Add(ip, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Has(ip)
	}
}
