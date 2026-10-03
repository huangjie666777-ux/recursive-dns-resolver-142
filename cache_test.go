package main

import (
	"net"

	"testing"
	"time"

	"github.com/miekg/dns"
)

func aRR(name, ip string, ttl uint32) *dns.A {
	a := &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}}
	a.A = net.ParseIP(ip).To4()
	return a
}

func TestCacheZeroTTLNotStored(t *testing.T) {
	c := NewCache(8)
	res := &resolution{answers: []dns.RR{aRR("x.test.", "10.0.0.1", 0)}, rcode: dns.RcodeSuccess}
	c.Store("x.test.", dns.TypeA, res, 0)
	if _, ok := c.Get("x.test.", dns.TypeA); ok {
		t.Fatal("zero-TTL result must not be cached")
	}
}

func TestCacheEvictsOldest(t *testing.T) {
	c := NewCache(2)
	mk := func(name string) *resolution {
		return &resolution{answers: []dns.RR{aRR(name, "10.0.0.1", 100)}, rcode: dns.RcodeSuccess}
	}
	c.Store("a.test.", dns.TypeA, mk("a.test."), 0)
	c.Store("b.test.", dns.TypeA, mk("b.test."), 0)
	c.Store("c.test.", dns.TypeA, mk("c.test."), 0)
	if c.Len() != 2 {
		t.Fatalf("len %d", c.Len())
	}
	if _, ok := c.Get("a.test.", dns.TypeA); ok {
		t.Fatal("oldest entry not evicted")
	}
}

func TestCacheTTLDecrements(t *testing.T) {
	c := NewCache(4)
	res := &resolution{answers: []dns.RR{aRR("x.test.", "10.0.0.1", 2)}, rcode: dns.RcodeSuccess}
	c.Store("x.test.", dns.TypeA, res, 0)
	time.Sleep(1100 * time.Millisecond)
	got, ok := c.Get("x.test.", dns.TypeA)
	if !ok {
		t.Fatal("entry should still be live")
	}
	if ttl := got.answers[0].Header().Ttl; ttl != 0 && ttl != 1 {
		t.Fatalf("ttl %d", ttl)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, ok := c.Get("x.test.", dns.TypeA); ok {
		t.Fatal("expired entry reused")
	}
}

func TestNegativeCacheAliasCap(t *testing.T) {
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Minttl: 120,
	}
	res := &resolution{rcode: dns.RcodeNameError, soa: soa}
	if ttl := cacheTTL(res, 0); ttl != 120 {
		t.Fatalf("want min(SOA TTL, MINIMUM)=120, got %d", ttl)
	}
	if ttl := cacheTTL(res, 30); ttl != 30 {
		t.Fatalf("want alias cap 30, got %d", ttl)
	}
}
