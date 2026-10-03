package main

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// cacheKey identifies a cached complete answer by case-insensitive name+type.
type cacheKey struct {
	name  string
	qtype uint16
}

// cacheEntry stores a full resolution result with original TTLs.
type cacheEntry struct {
	key      cacheKey
	rcode    int      // dns.RcodeSuccess or dns.RcodeNameError
	answer   []dns.RR // full CNAME chain + final records (may be nil for negative)
	soa      *dns.SOA // authority SOA for negative answers
	storedAt time.Time
	ttl      uint32        // lifetime of the whole entry in seconds
	elem     *list.Element // position in LRU list
}

// Cache is a bounded LRU cache of complete resolution results.
type Cache struct {
	mu         sync.Mutex
	maxEntries int
	maxNegTTL  uint32
	items      map[cacheKey]*cacheEntry
	lru        *list.List // front = most recently used, values are *cacheEntry
}

func newCache(maxEntries int, maxNegTTL uint32) *Cache {
	if maxEntries <= 0 {
		maxEntries = 1
	}
	return &Cache{
		maxEntries: maxEntries,
		maxNegTTL:  maxNegTTL,
		items:      make(map[cacheKey]*cacheEntry),
		lru:        list.New(),
	}
}

func keyFor(name string, qtype uint16) cacheKey {
	return cacheKey{name: strings.ToLower(dns.Fqdn(name)), qtype: qtype}
}

// minTTL returns the smallest TTL among records, and whether any record exists.
func minTTL(rrs []dns.RR) (uint32, bool) {
	var m uint32
	found := false
	for i, rr := range rrs {
		t := rr.Header().Ttl
		if i == 0 || t < m {
			m = t
		}
		found = true
	}
	return m, found
}

// putPositive caches a complete successful answer chain. Zero-TTL answers are
// never cached.
func (c *Cache) putPositive(name string, qtype uint16, answer []dns.RR) {
	ttl, ok := minTTL(answer)
	if !ok || ttl == 0 {
		return
	}
	c.put(&cacheEntry{
		key:      keyFor(name, qtype),
		rcode:    dns.RcodeSuccess,
		answer:   copyRRs(answer),
		storedAt: time.Now(),
		ttl:      ttl,
	})
}

// putNegative caches NXDOMAIN / NODATA only when an SOA is present. Lifetime is
// min(SOA TTL, SOA MINIMUM, configured cap), further limited by the TTL of any
// CNAME chain leading to the negative answer.
func (c *Cache) putNegative(name string, qtype uint16, rcode int, chain []dns.RR, soa *dns.SOA) {
	if soa == nil {
		return
	}
	ttl := soa.Hdr.Ttl
	if soa.Minttl < ttl {
		ttl = soa.Minttl
	}
	if c.maxNegTTL > 0 && ttl > c.maxNegTTL {
		ttl = c.maxNegTTL
	}
	if chainTTL, ok := minTTL(chain); ok && chainTTL < ttl {
		ttl = chainTTL
	}
	if ttl == 0 {
		return
	}
	c.put(&cacheEntry{
		key:      keyFor(name, qtype),
		rcode:    rcode,
		answer:   copyRRs(chain),
		soa:      dns.Copy(soa).(*dns.SOA),
		storedAt: time.Now(),
		ttl:      ttl,
	})
}

func (c *Cache) put(e *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.items[e.key]; ok {
		c.lru.Remove(old.elem)
		delete(c.items, old.key)
	}
	e.elem = c.lru.PushFront(e)
	c.items[e.key] = e
	for len(c.items) > c.maxEntries {
		back := c.lru.Back()
		if back == nil {
			break
		}
		victim := back.Value.(*cacheEntry)
		delete(c.items, victim.key)
		c.lru.Remove(back)
	}
}

// get returns a cached result with per-record TTLs decremented by the elapsed
// time. Expired entries are removed and not reused. Returned records are fresh
// copies so concurrent handlers never share mutable state.
func (c *Cache) get(name string, qtype uint16) (rcode int, answer []dns.RR, soa *dns.SOA, ok bool) {
	key := keyFor(name, qtype)
	c.mu.Lock()
	e, hit := c.items[key]
	if hit {
		c.lru.MoveToFront(e.elem)
	}
	c.mu.Unlock()
	if !hit {
		return 0, nil, nil, false
	}
	elapsed := uint32(time.Since(e.storedAt).Seconds())
	if elapsed >= e.ttl {
		c.mu.Lock()
		if cur, ok := c.items[key]; ok && cur == e {
			delete(c.items, key)
			c.lru.Remove(e.elem)
		}
		c.mu.Unlock()
		return 0, nil, nil, false
	}
	remaining := e.ttl - elapsed
	for _, rr := range e.answer {
		cp := dns.Copy(rr)
		hdr := cp.Header()
		if elapsed >= hdr.Ttl {
			hdr.Ttl = 0
		} else {
			hdr.Ttl = hdr.Ttl - elapsed
		}
		answer = append(answer, cp)
	}
	if e.soa != nil {
		s := dns.Copy(e.soa).(*dns.SOA)
		if elapsed >= s.Hdr.Ttl {
			s.Hdr.Ttl = 0
		} else {
			s.Hdr.Ttl = s.Hdr.Ttl - elapsed
		}
		soa = s
	}
	_ = remaining
	return e.rcode, answer, soa, true
}

func copyRRs(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, dns.Copy(rr))
	}
	return out
}
