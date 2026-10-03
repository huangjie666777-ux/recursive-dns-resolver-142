package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	errBudget   = errors.New("upstream query budget exhausted")
	errDeadline = errors.New("resolution deadline exceeded")
	errNoNS     = errors.New("no reachable nameserver")
	errLoop     = errors.New("resolution loop detected")
)

// resolveResult is a complete, cacheable terminal answer.
type resolveResult struct {
	rcode  int      // dns.RcodeSuccess or dns.RcodeNameError
	answer []dns.RR // full CNAME chain plus final address records
	soa    *dns.SOA // authority SOA for negative results
}

// resolveState tracks per-query limits shared across sub-resolutions.
type resolveState struct {
	deadline time.Time
	budget   int
	nsStack  map[string]bool // NS names currently being resolved (dependency loop guard)
}

func (r *Resolver) newState() *resolveState {
	return &resolveState{
		deadline: time.Now().Add(time.Duration(r.cfg.QueryDeadlineSec) * time.Second),
		budget:   r.cfg.MaxUpstream,
		nsStack:  make(map[string]bool),
	}
}

func (st *resolveState) spend() error {
	if time.Now().After(st.deadline) {
		return errDeadline
	}
	if st.budget <= 0 {
		return errBudget
	}
	st.budget--
	return nil
}

// Resolver performs iterative recursion from the root using only in-memory
// state.
type Resolver struct {
	cfg   *Config
	cache *Cache
	up    *upstreamClient

	mu       sync.Mutex
	inflight map[cacheKey]*flight
}

type flight struct {
	done chan struct{}
	res  *resolveResult
	err  error
}

func newResolver(cfg *Config) *Resolver {
	return &Resolver{
		cfg:      cfg,
		cache:    newCache(cfg.CacheMaxEntries, cfg.CacheMaxNegTTL),
		up:       newUpstreamClient(cfg.UpstreamPort, time.Duration(cfg.UpstreamTimeoutMs)*time.Millisecond),
		inflight: make(map[cacheKey]*flight),
	}
}

// Resolve answers one A/AAAA question, deduplicating concurrent identical
// queries. Every caller receives independent record copies.
func (r *Resolver) Resolve(qname string, qtype uint16) (*resolveResult, error) {
	key := keyFor(qname, qtype)

	r.mu.Lock()
	if f, ok := r.inflight[key]; ok {
		r.mu.Unlock()
		<-f.done
		if f.err != nil {
			return nil, f.err
		}
		return cloneResult(f.res), nil
	}
	f := &flight{done: make(chan struct{})}
	r.inflight[key] = f
	r.mu.Unlock()

	res, err := r.resolveWithCache(qname, qtype, r.newState())

	r.mu.Lock()
	delete(r.inflight, key)
	r.mu.Unlock()
	f.res, f.err = res, err
	close(f.done)
	if err != nil {
		return nil, err
	}
	return cloneResult(res), nil
}

func cloneResult(res *resolveResult) *resolveResult {
	out := &resolveResult{rcode: res.rcode, answer: copyRRs(res.answer)}
	if res.soa != nil {
		out.soa = dns.Copy(res.soa).(*dns.SOA)
	}
	return out
}

// resolveWithCache consults the cache, resolves on miss, and stores complete
// cacheable results. SERVFAIL (error) results are never cached.
func (r *Resolver) resolveWithCache(qname string, qtype uint16, st *resolveState) (*resolveResult, error) {
	if rcode, answer, soa, ok := r.cache.get(qname, qtype); ok {
		return &resolveResult{rcode: rcode, answer: answer, soa: soa}, nil
	}
	res, err := r.resolveIterative(dns.Fqdn(qname), qtype, st)
	if err != nil {
		return nil, err
	}
	if res.rcode == dns.RcodeSuccess && len(res.answer) > 0 {
		r.cache.putPositive(qname, qtype, res.answer)
	} else if res.soa != nil {
		r.cache.putNegative(qname, qtype, res.rcode, res.answer, res.soa)
	}
	return res, nil
}

// resolveIterative follows CNAMEs, delegating each name from the root.
func (r *Resolver) resolveIterative(qname string, qtype uint16, st *resolveState) (*resolveResult, error) {
	var chain []dns.RR
	seen := map[string]bool{dns.CanonicalName(qname): true}
	name := qname

	for {
		step, err := r.resolveFromRoot(name, qtype, st)
		if err != nil {
			return nil, err
		}
		switch {
		case len(step.final) > 0:
			return &resolveResult{rcode: dns.RcodeSuccess, answer: append(chain, step.final...)}, nil
		case step.cname != nil:
			target := step.cname.Target
			if seen[dns.CanonicalName(target)] {
				return nil, fmt.Errorf("%w: CNAME loop at %s", errLoop, target)
			}
			seen[dns.CanonicalName(target)] = true
			chain = append(chain, dns.Copy(step.cname))
			// A cached answer for the alias target completes the chain.
			if rcode, cached, soa, ok := r.cache.get(target, qtype); ok {
				return &resolveResult{rcode: rcode, answer: append(chain, cached...), soa: soa}, nil
			}
			name = dns.Fqdn(target)
		case step.negative != nil:
			return &resolveResult{rcode: step.negative.rcode, answer: chain, soa: step.negative.soa}, nil
		}
	}
}

type negativeAnswer struct {
	rcode int
	soa   *dns.SOA
}

type stepResult struct {
	final    []dns.RR
	cname    *dns.CNAME
	negative *negativeAnswer
}

// resolveFromRoot iteratively chases delegations from the root hints down to
// the authoritative server for name.
func (r *Resolver) resolveFromRoot(name string, qtype uint16, st *resolveState) (*stepResult, error) {
	zone := "."
	servers := make([]string, 0, len(r.cfg.RootHints))
	for _, h := range r.cfg.RootHints {
		servers = append(servers, h.IPv4)
	}

	for depth := 0; depth < r.cfg.MaxDepth; depth++ {
		resp, err := r.queryAny(servers, name, qtype, st)
		if err != nil {
			return nil, err
		}

		if resp.Rcode == dns.RcodeNameError {
			return &stepResult{negative: &negativeAnswer{rcode: dns.RcodeNameError, soa: findSOA(resp.Ns)}}, nil
		}
		if resp.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("upstream rcode %s from zone %s", dns.RcodeToString[resp.Rcode], zone)
		}

		// Accept only authoritative terminal answers for the exact name.
		if resp.Authoritative {
			var finals []dns.RR
			for _, rr := range resp.Answer {
				hdr := rr.Header()
				if !equalNames(hdr.Name, name) {
					continue
				}
				if hdr.Rrtype == qtype {
					finals = append(finals, rr)
				}
			}
			if len(finals) > 0 {
				return &stepResult{final: copyRRs(finals)}, nil
			}
			for _, rr := range resp.Answer {
				if cn, ok := rr.(*dns.CNAME); ok && equalNames(cn.Hdr.Name, name) {
					return &stepResult{cname: dns.Copy(cn).(*dns.CNAME)}, nil
				}
			}
			// Authoritative answer with neither data nor CNAME: NODATA.
			return &stepResult{negative: &negativeAnswer{rcode: dns.RcodeSuccess, soa: findSOA(resp.Ns)}}, nil
		}

		// Otherwise expect a delegation: NS records for a zone that is an
		// ancestor of the query name and strictly deeper than the current zone.
		delegZone, nsNames := bestDelegation(resp.Ns, name, zone)
		if delegZone == "" {
			return nil, fmt.Errorf("non-authoritative answer without usable delegation for %s", name)
		}
		glue := glueAddrs(resp.Extra, delegZone, nsNames)
		for _, ns := range nsNames {
			if _, ok := glue[strings.ToLower(ns)]; ok {
				continue
			}
			ips, err := r.resolveNSAddr(ns, st)
			if err != nil {
				continue // try other NS names
			}
			if len(ips) > 0 {
				glue[strings.ToLower(ns)] = ips
			}
		}
		var next []string
		for _, ips := range glue {
			next = append(next, ips...)
		}
		if len(next) == 0 {
			return nil, errNoNS
		}
		zone, servers = delegZone, next
	}
	return nil, fmt.Errorf("delegation depth limit exceeded for %s", name)
}

// queryAny tries each server in turn until one answers; upstream failures move
// to the next server. All failures surface as one error (SERVFAIL upstream).
func (r *Resolver) queryAny(servers []string, name string, qtype uint16, st *resolveState) (*dns.Msg, error) {
	var lastErr error
	for _, srv := range servers {
		if err := st.spend(); err != nil {
			return nil, err
		}
		resp, err := r.up.exchange(srv, name, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errNoNS
	}
	return nil, fmt.Errorf("all nameservers failed for %s: %w", name, lastErr)
}

// resolveNSAddr independently recurses for an out-of-bailiwick NS address,
// guarding against resolution dependency loops.
func (r *Resolver) resolveNSAddr(nsName string, st *resolveState) ([]string, error) {
	key := dns.CanonicalName(nsName)
	if st.nsStack[key] {
		return nil, fmt.Errorf("%w: NS dependency on %s", errLoop, nsName)
	}
	st.nsStack[key] = true
	defer delete(st.nsStack, key)

	res, err := r.resolveWithCache(nsName, dns.TypeA, st)
	if err != nil || res.rcode != dns.RcodeSuccess {
		return nil, errNoNS
	}
	var ips []string
	for _, rr := range res.answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	if len(ips) == 0 {
		return nil, errNoNS
	}
	return ips, nil
}

// bestDelegation picks the deepest NS owner in ns that is an ancestor of name
// and strictly below curZone. Returns the zone and its NS target names.
func bestDelegation(ns []dns.RR, name, curZone string) (string, []string) {
	best := ""
	var targets []string
	for _, rr := range ns {
		n, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.CanonicalName(n.Hdr.Name)
		if owner == dns.CanonicalName(curZone) {
			continue // must be deeper than the current zone
		}
		if !dns.IsSubDomain(owner, name) {
			continue // delegation must be an ancestor of the query name
		}
		if best == "" || dns.CountLabel(owner) > dns.CountLabel(best) {
			best = owner
			targets = nil
		}
		if dns.CanonicalName(n.Hdr.Name) == best {
			targets = append(targets, n.Ns)
		}
	}
	return best, targets
}

// glueAddrs trusts only A records in the additional section whose owner is one
// of the delegated NS names and lies inside the delegated zone.
func glueAddrs(extra []dns.RR, zone string, nsNames []string) map[string][]string {
	inSet := make(map[string]bool, len(nsNames))
	for _, n := range nsNames {
		inSet[dns.CanonicalName(n)] = true
	}
	out := make(map[string][]string)
	for _, rr := range extra {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		owner := dns.CanonicalName(a.Hdr.Name)
		if !inSet[owner] || !dns.IsSubDomain(zone, owner) {
			continue
		}
		out[strings.ToLower(a.Hdr.Name)] = append(out[strings.ToLower(a.Hdr.Name)], a.A.String())
	}
	return out
}

func findSOA(rrs []dns.RR) *dns.SOA {
	for _, rr := range rrs {
		if s, ok := rr.(*dns.SOA); ok {
			return dns.Copy(s).(*dns.SOA)
		}
	}
	return nil
}
