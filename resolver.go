package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	errCNAMELoop     = errors.New("CNAME loop detected")
	errDependLoop    = errors.New("resolution dependency loop detected")
	errBudget        = errors.New("upstream query budget exhausted")
	errDeadline      = errors.New("resolution deadline exceeded")
	errAllFailed     = errors.New("all authoritative servers failed")
	errNoUsableNS    = errors.New("delegation without usable nameserver addresses")
	errTooDeep       = errors.New("too many delegations")
	errBadDelegation = errors.New("invalid delegation")
)

const maxDelegations = 32

// Resolver performs iterative resolution starting from the root hints.
// It never uses the system resolver or a forwarding recursor; all state
// is in memory and no DNSSEC validation is performed.
type Resolver struct {
	cfg   *Config
	cache *Cache

	upstreamTotal atomic.Int64 // diagnostic: upstream queries sent
}

func NewResolver(cfg *Config) *Resolver {
	return &Resolver{cfg: cfg, cache: NewCache(cfg.CacheMaxEntries)}
}

// Cache exposes the resolver cache (used by tests).
func (r *Resolver) Cache() *Cache { return r.cache }

// session carries per-query limits shared across every sub-resolution
// (CNAME targets, nameserver address lookups).
type session struct {
	deadline time.Time
	budget   int
	stack    []string // lower-cased names currently being resolved
}

// Resolve resolves one (name, qtype) pair to a complete result.
func (r *Resolver) Resolve(name string, qtype uint16) (*resolution, error) {
	s := &session{
		deadline: time.Now().Add(r.cfg.resolveTimeout),
		budget:   r.cfg.MaxUpstreamQueries,
	}
	return r.resolveChain(s, dns.Fqdn(name), qtype)
}

// resolveChain resolves name/qtype following CNAMEs to the terminal
// answer, returning the full chain. It detects alias loops and
// resolution dependency loops, and caches complete results.
func (r *Resolver) resolveChain(s *session, name string, qtype uint16) (*resolution, error) {
	lname := strings.ToLower(dns.Fqdn(name))
	for _, n := range s.stack {
		if n == lname {
			return nil, errDependLoop
		}
	}
	s.stack = append(s.stack, lname)
	defer func() { s.stack = s.stack[:len(s.stack)-1] }()

	if cached, ok := r.cache.Get(lname, qtype); ok {
		return cached, nil
	}

	visited := make(map[string]bool)
	var chain []dns.RR
	var aliasCap uint32
	cur := dns.Fqdn(name)
	var final *resolution
	for {
		key := strings.ToLower(cur)
		if visited[key] {
			return nil, errCNAMELoop
		}
		visited[key] = true

		res, err := r.resolveDirect(s, cur, qtype)
		if err != nil {
			return nil, err
		}
		var cname *dns.CNAME
		var finals []dns.RR
		for _, rr := range res.answers {
			if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, cur) && cname == nil {
				cname = c
				continue
			}
			finals = append(finals, rr)
		}
		if cname != nil {
			chain = append(chain, cname)
			if aliasCap == 0 || cname.Hdr.Ttl < aliasCap {
				aliasCap = cname.Hdr.Ttl
			}
		}
		if len(finals) > 0 || res.rcode != dns.RcodeSuccess || cname == nil {
			chain = append(chain, finals...)
			final = &resolution{answers: chain, rcode: res.rcode, soa: res.soa}
			break
		}
		cur = dns.Fqdn(cname.Target)
	}

	// Only complete results reach the cache: positive chains, or
	// negative results carrying a SOA. SERVFAIL paths return early
	// above and partial chains are never stored.
	r.cache.Store(lname, qtype, final, aliasCap)
	return final, nil
}

// resolveDirect iteratively resolves one exact (name, qtype) from the
// root down, following delegations. CNAMEs in the answer are returned
// as-is for resolveChain to follow.
func (r *Resolver) resolveDirect(s *session, name string, qtype uint16) (*resolution, error) {
	zone := "."
	servers := r.cfg.RootHints
	for depth := 0; depth < maxDelegations; depth++ {
		resp, err := r.querySome(s, servers, name, qtype)
		if err != nil {
			return nil, err
		}
		switch resp.Rcode {
		case dns.RcodeNameError:
			return &resolution{rcode: dns.RcodeNameError, soa: findSOA(resp.Ns)}, nil
		case dns.RcodeSuccess:
		default:
			return nil, fmt.Errorf("upstream rcode %s", dns.RcodeToString[resp.Rcode])
		}

		if len(resp.Answer) > 0 {
			return &resolution{answers: resp.Answer, rcode: dns.RcodeSuccess}, nil
		}

		childZone, nsNames := findDelegation(resp.Ns, zone, name)
		if childZone == "" {
			// No delegation: NODATA if a SOA proves it, otherwise the
			// upstream answer is unusable.
			if soa := findSOA(resp.Ns); soa != nil {
				return &resolution{rcode: dns.RcodeSuccess, soa: soa}, nil
			}
			return nil, errors.New("empty answer without delegation or SOA")
		}

		// Glue: only A records in Additional owned by one of the
		// delegated NS names and inside the delegated domain.
		addrs := glueAddrs(resp.Extra, childZone, nsNames)
		// NS names without trusted glue are resolved independently.
		for _, ns := range nsNames {
			if hasAddrFor(addrs, ns) {
				continue
			}
			res, err := r.resolveChain(s, ns, dns.TypeA)
			if err != nil {
				continue // try other nameservers
			}
			for _, rr := range res.answers {
				if a, ok := rr.(*dns.A); ok && strings.EqualFold(a.Hdr.Name, ns) {
					addrs = append(addrs, nsAddr{ns: ns, ip: a.A.String()})
				}
			}
		}
		if len(addrs) == 0 {
			return nil, errNoUsableNS
		}
		zone = childZone
		servers = addrsToIPs(addrs)
	}
	return nil, errTooDeep
}

type nsAddr struct {
	ns string
	ip string
}

func hasAddrFor(addrs []nsAddr, ns string) bool {
	for _, a := range addrs {
		if strings.EqualFold(a.ns, ns) {
			return true
		}
	}
	return false
}

func addrsToIPs(addrs []nsAddr) []string {
	seen := make(map[string]bool)
	var ips []string
	for _, a := range addrs {
		if !seen[a.ip] {
			seen[a.ip] = true
			ips = append(ips, a.ip)
		}
	}
	return ips
}

// findDelegation extracts the deepest NS delegation from an authority
// section. The delegated zone must be an ancestor of (or equal to) the
// question name and strictly deeper than the current zone.
func findDelegation(ns []dns.RR, curZone, qname string) (string, []string) {
	best := ""
	var names []string
	for _, rr := range ns {
		n, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.Fqdn(n.Hdr.Name)
		if !dns.IsSubDomain(owner, qname) {
			continue // delegated zone must be an ancestor of the question
		}
		if dns.CountLabel(owner) <= dns.CountLabel(curZone) {
			continue // must be deeper than the current zone
		}
		if best == "" || dns.CountLabel(owner) > dns.CountLabel(best) {
			best = owner
			names = nil
		}
		if strings.EqualFold(owner, best) {
			names = append(names, dns.Fqdn(n.Ns))
		}
	}
	return best, names
}

// glueAddrs keeps only A records from the additional section whose
// owner is one of the delegated NS names and lies inside the delegated
// domain. Everything else is untrusted.
func glueAddrs(extra []dns.RR, childZone string, nsNames []string) []nsAddr {
	var addrs []nsAddr
	for _, rr := range extra {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		owner := dns.Fqdn(a.Hdr.Name)
		if !dns.IsSubDomain(childZone, owner) {
			continue
		}
		for _, ns := range nsNames {
			if strings.EqualFold(owner, ns) {
				addrs = append(addrs, nsAddr{ns: owner, ip: a.A.String()})
			}
		}
	}
	return addrs
}

func findSOA(ns []dns.RR) *dns.SOA {
	for _, rr := range ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

// querySome tries each server in turn; timeouts and failures move to
// the next nameserver. Only when all fail does it give up.
func (r *Resolver) querySome(s *session, servers []string, name string, qtype uint16) (*dns.Msg, error) {
	var lastErr error = errAllFailed
	for _, srv := range servers {
		resp, err := r.exchange(s, srv, name, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

// exchange sends one RD=0 query, validating the source, transaction ID
// and question, and retries over TCP to the same server when the UDP
// response is truncated.
func (r *Resolver) exchange(s *session, server, name string, qtype uint16) (*dns.Msg, error) {
	addr := net.JoinHostPort(server, strconv.Itoa(r.cfg.UpstreamPort))
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = false

	resp, err := r.doExchange(s, m, addr, "udp")
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		resp, err = r.doExchange(s, m, addr, "tcp")
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (r *Resolver) doExchange(s *session, m *dns.Msg, addr, network string) (*dns.Msg, error) {
	if s.budget <= 0 {
		return nil, errBudget
	}
	remain := time.Until(s.deadline)
	if remain <= 0 {
		return nil, errDeadline
	}
	s.budget--
	r.upstreamTotal.Add(1)

	timeout := r.cfg.upstreamTimeout
	if remain < timeout {
		timeout = remain
	}
	c := &dns.Client{Net: network, Timeout: timeout}
	resp, _, err := c.Exchange(m, addr) // connected socket: source validated
	if err != nil {
		return nil, err
	}
	if err := validateResponse(m, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// validateResponse checks transaction ID and echoed question.
func validateResponse(req, resp *dns.Msg) error {
	if !resp.Response {
		return errors.New("upstream message is not a response")
	}
	if resp.Id != req.Id {
		return errors.New("transaction ID mismatch")
	}
	if len(resp.Question) != 1 || len(req.Question) != 1 {
		return errors.New("question count mismatch")
	}
	q, rq := resp.Question[0], req.Question[0]
	if !strings.EqualFold(q.Name, rq.Name) || q.Qtype != rq.Qtype || q.Qclass != rq.Qclass {
		return errors.New("question mismatch")
	}
	return nil
}
