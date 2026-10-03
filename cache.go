package main

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// resolution is a complete outcome for one (name, type) pair: the full
// answer chain (CNAMEs included), the final rcode and, for negative
// results, the authority SOA.
type resolution struct {
	answers []dns.RR
	rcode   int
	soa     *dns.SOA
}

type cacheKey struct {
	name  string // lower-cased FQDN
	qtype uint16
}

type cacheEntry struct {
	res    *resolution
	stored time.Time
	ttl    uint32
}

// Cache is a concurrency-safe, size-bounded result cache. Keys are
// case-insensitive names plus qtype. SERVFAIL outcomes and partial
// chains are never stored.
type Cache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[cacheKey]*cacheEntry
	order      []cacheKey // FIFO eviction
}

func NewCache(maxEntries int) *Cache {
	return &Cache{maxEntries: maxEntries, entries: make(map[cacheKey]*cacheEntry)}
}

// Get returns a copy of the cached resolution with every record TTL
// decremented by the elapsed time. Expired and zero-TTL entries are
// dropped and never reused.
func (c *Cache) Get(name string, qtype uint16) (*resolution, bool) {
	key := cacheKey{name: strings.ToLower(dns.Fqdn(name)), qtype: qtype}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	age := uint32(time.Since(e.stored) / time.Second)
	if age >= e.ttl {
		c.remove(key)
		return nil, false
	}
	return cloneResolution(e.res, age), true
}

// Store caches a complete resolution. aliasCap limits negative caching
// by the smallest CNAME TTL in the chain. Non-cacheable outcomes
// (no answers and no SOA, zero TTL) are silently skipped.
func (c *Cache) Store(name string, qtype uint16, res *resolution, aliasCap uint32) {
	ttl := cacheTTL(res, aliasCap)
	if ttl == 0 {
		return
	}
	key := cacheKey{name: strings.ToLower(dns.Fqdn(name)), qtype: qtype}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; !ok {
		c.order = append(c.order, key)
	}
	c.entries[key] = &cacheEntry{res: res, stored: time.Now(), ttl: ttl}
	for len(c.entries) > c.maxEntries && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		if oldest != key {
			delete(c.entries, oldest)
		}
	}
}

func (c *Cache) remove(key cacheKey) {
	delete(c.entries, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

// Len reports the number of live entries (test helper).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// cacheTTL derives the cache lifetime of a complete result.
func cacheTTL(res *resolution, aliasCap uint32) uint32 {
	if res.rcode == dns.RcodeSuccess && len(res.answers) > 0 {
		// Positive: smallest TTL across the whole answer chain.
		return minTTL(res)
	}
	if res.soa != nil {
		// Negative (NXDOMAIN / NODATA): only cached when a SOA exists;
		// min(SOA TTL, SOA MINIMUM), capped by the alias TTL.
		ttl := res.soa.Hdr.Ttl
		if res.soa.Minttl < ttl {
			ttl = res.soa.Minttl
		}
		if aliasCap > 0 && aliasCap < ttl {
			ttl = aliasCap
		}
		return ttl
	}
	return 0
}

func minTTL(res *resolution) uint32 {
	ttl := uint32(1<<31 - 1)
	for _, rr := range res.answers {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	return ttl
}

// cloneResolution deep-copies a resolution, subtracting secs from every
// record TTL (saturating at zero).
func cloneResolution(res *resolution, secs uint32) *resolution {
	out := &resolution{rcode: res.rcode}
	sub := func(ttl uint32) uint32 {
		if secs >= ttl {
			return 0
		}
		return ttl - secs
	}
	for _, rr := range res.answers {
		cp := dns.Copy(rr)
		cp.Header().Ttl = sub(rr.Header().Ttl)
		out.answers = append(out.answers, cp)
	}
	if res.soa != nil {
		cp := dns.Copy(res.soa).(*dns.SOA)
		cp.Hdr.Ttl = sub(res.soa.Hdr.Ttl)
		out.soa = cp
	}
	return out
}
