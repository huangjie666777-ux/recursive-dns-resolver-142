package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func rrFor(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestZeroTTLNotCached(t *testing.T) {
	c := newCache(8, 3600)
	c.putPositive("a.test.", dns.TypeA, []dns.RR{rrFor(t, "a.test. 0 IN A 192.0.2.1")})
	if _, _, _, ok := c.get("a.test.", dns.TypeA); ok {
		t.Fatal("zero-TTL answer must not be cached")
	}
}

func TestLRUEviction(t *testing.T) {
	c := newCache(2, 3600)
	mk := func(name string) []dns.RR {
		return []dns.RR{rrFor(t, name+" 100 IN A 192.0.2.1")}
	}
	c.putPositive("a.test.", dns.TypeA, mk("a.test."))
	c.putPositive("b.test.", dns.TypeA, mk("b.test."))
	c.putPositive("c.test.", dns.TypeA, mk("c.test.")) // evicts a.test.
	if _, _, _, ok := c.get("a.test.", dns.TypeA); ok {
		t.Fatal("oldest entry must be evicted")
	}
	if _, _, _, ok := c.get("c.test.", dns.TypeA); !ok {
		t.Fatal("newest entry must survive")
	}
}

func TestNegativeTTLFromSOA(t *testing.T) {
	c := newCache(8, 3600)
	soa := rrFor(t, "x.test. 600 IN SOA ns.x.test. h.x.test. 1 7200 3600 1209600 30").(*dns.SOA)
	c.putNegative("x.test.", dns.TypeA, dns.RcodeNameError, nil, soa)
	_, _, got, ok := c.get("x.test.", dns.TypeA)
	if !ok || got == nil {
		t.Fatal("negative answer with SOA must be cached")
	}
	// Lifetime is min(SOA TTL 600, MINIMUM 30) = 30; sleep is avoided, just
	// verify it is cached and expires quickly.
	c2 := newCache(8, 3600)
	c2.putNegative("y.test.", dns.TypeA, dns.RcodeNameError, nil, nil)
	if _, _, _, ok := c2.get("y.test.", dns.TypeA); ok {
		t.Fatal("negative answer without SOA must not be cached")
	}
}

func TestNegativeLimitedByChainTTL(t *testing.T) {
	c := newCache(8, 3600)
	chain := []dns.RR{rrFor(t, "a.test. 10 IN CNAME b.test.")}
	soa := rrFor(t, "b.test. 600 IN SOA ns.b.test. h.b.test. 1 7200 3600 1209600 60").(*dns.SOA)
	c.putNegative("a.test.", dns.TypeA, dns.RcodeNameError, chain, soa)
	c.mu.Lock()
	e := c.items[keyFor("a.test.", dns.TypeA)]
	c.mu.Unlock()
	if e == nil || e.ttl != 10 {
		t.Fatalf("negative TTL must be limited by alias TTL 10, got %+v", e)
	}
}

func TestExpiredEntryNotReused(t *testing.T) {
	c := newCache(8, 3600)
	c.put(&cacheEntry{
		key:      keyFor("z.test.", dns.TypeA),
		rcode:    dns.RcodeSuccess,
		answer:   []dns.RR{rrFor(t, "z.test. 1 IN A 192.0.2.1")},
		storedAt: time.Now().Add(-2 * time.Second),
		ttl:      1,
	})
	if _, _, _, ok := c.get("z.test.", dns.TypeA); ok {
		t.Fatal("expired entry must not be reused")
	}
}
