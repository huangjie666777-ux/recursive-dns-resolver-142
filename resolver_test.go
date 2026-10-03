package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testPort = 15354

var treeOnce sync.Once

// startTestTree brings up the four-level authority tree on 127.0.0.2-5.
func startTestTree(t *testing.T) *Resolver {
	t.Helper()
	treeOnce.Do(func() {
		if _, err := startDemoAuthorities(testPort); err != nil {
			panic(err)
		}
	})
	cfg := &Config{
		ListenAddr:         "127.0.0.1:18053",
		RootHints:          []string{"127.0.0.2"},
		UpstreamPort:       testPort,
		UpstreamTimeoutMs:  1000,
		ResolveTimeoutMs:   5000,
		MaxUpstreamQueries: 64,
		CacheMaxEntries:    16,
	}
	cfg.setDefaults()
	return NewResolver(cfg)
}

func mustResolve(t *testing.T, r *Resolver, name string, qtype uint16) *resolution {
	t.Helper()
	res, err := r.Resolve(name, qtype)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return res
}

func aRecord(t *testing.T, res *resolution) *dns.A {
	t.Helper()
	for _, rr := range res.answers {
		if a, ok := rr.(*dns.A); ok {
			return a
		}
	}
	t.Fatal("no A record in answer")
	return nil
}

func TestResolveViaGlue(t *testing.T) {
	r := startTestTree(t)
	res := mustResolve(t, r, "www.corp.test.", dns.TypeA)
	if got := aRecord(t, res).A.String(); got != "192.0.2.10" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveDeeperDelegation(t *testing.T) {
	r := startTestTree(t)
	res := mustResolve(t, r, "WWW.DEPT.CORP.TEST.", dns.TypeA) // case-insensitive
	if got := aRecord(t, res).A.String(); got != "192.0.2.20" {
		t.Fatalf("got %s", got)
	}
}

func TestResolveGluelessNS(t *testing.T) {
	r := startTestTree(t)
	// eng.corp.test. is delegated without glue; the resolver must
	// independently resolve ns1.eng.corp.test. first.
	res := mustResolve(t, r, "www.eng.corp.test.", dns.TypeA)
	if got := aRecord(t, res).A.String(); got != "192.0.2.30" {
		t.Fatalf("got %s", got)
	}
}

func TestCNAMEChain(t *testing.T) {
	r := startTestTree(t)
	res := mustResolve(t, r, "alias.dept.corp.test.", dns.TypeA)
	var sawCNAME bool
	for _, rr := range res.answers {
		if c, ok := rr.(*dns.CNAME); ok {
			sawCNAME = true
			if !strings.EqualFold(c.Target, "www.dept.corp.test.") {
				t.Fatalf("bad target %s", c.Target)
			}
		}
	}
	if !sawCNAME {
		t.Fatal("CNAME missing from chain")
	}
	if got := aRecord(t, res).A.String(); got != "192.0.2.20" {
		t.Fatalf("got %s", got)
	}
}

func TestCNAMELoop(t *testing.T) {
	r := startTestTree(t)
	if _, err := r.Resolve("loop1.dept.corp.test.", dns.TypeA); err != errCNAMELoop {
		t.Fatalf("want CNAME loop error, got %v", err)
	}
}

func TestNXDOMAIN(t *testing.T) {
	r := startTestTree(t)
	res := mustResolve(t, r, "nosuch.dept.corp.test.", dns.TypeA)
	if res.rcode != dns.RcodeNameError {
		t.Fatalf("rcode %s", dns.RcodeToString[res.rcode])
	}
	if res.soa == nil {
		t.Fatal("negative answer without SOA")
	}
}

func TestNODATA(t *testing.T) {
	r := startTestTree(t)
	res := mustResolve(t, r, "txt-only.dept.corp.test.", dns.TypeA)
	if res.rcode != dns.RcodeSuccess || len(res.answers) != 0 {
		t.Fatalf("want NODATA, got rcode=%s answers=%d", dns.RcodeToString[res.rcode], len(res.answers))
	}
	if res.soa == nil {
		t.Fatal("NODATA without SOA")
	}
}

func TestCacheHitAndTTLDecay(t *testing.T) {
	r := startTestTree(t)
	first := mustResolve(t, r, "www.corp.test.", dns.TypeA)
	before := r.upstreamTotal.Load()
	second := mustResolve(t, r, "WWW.CORP.TEST.", dns.TypeA) // cache keys ignore case
	if after := r.upstreamTotal.Load(); after != before {
		t.Fatalf("cache miss: upstream queries %d -> %d", before, after)
	}
	ttl1 := aRecord(t, first).Hdr.Ttl
	ttl2 := aRecord(t, second).Hdr.Ttl
	if ttl2 > ttl1 {
		t.Fatalf("TTL did not decay: %d -> %d", ttl1, ttl2)
	}
	if len(second.answers) != len(first.answers) {
		t.Fatal("cached chain changed shape")
	}
}

func TestNegativeCached(t *testing.T) {
	r := startTestTree(t)
	mustResolve(t, r, "nosuch.dept.corp.test.", dns.TypeA)
	before := r.upstreamTotal.Load()
	res := mustResolve(t, r, "nosuch.dept.corp.test.", dns.TypeA)
	if res.rcode != dns.RcodeNameError {
		t.Fatal("cached negative lost rcode")
	}
	if after := r.upstreamTotal.Load(); after != before {
		t.Fatal("negative result not cached")
	}
}

func TestBudgetExhaustionIsSERVFAILPath(t *testing.T) {
	r := startTestTree(t)
	r.cfg.MaxUpstreamQueries = 1 // root delegation alone needs more
	if _, err := r.Resolve("www.dept.corp.test.", dns.TypeA); err != errBudget {
		t.Fatalf("want budget error, got %v", err)
	}
}

func TestServerRoundTrip(t *testing.T) {
	r := startTestTree(t)
	cfg := *r.cfg
	srv := NewServer(&cfg, r)
	if err := srv.ActivateAndServe(); err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	time.Sleep(100 * time.Millisecond)

	m := new(dns.Msg)
	m.SetQuestion("www.dept.corp.test.", dns.TypeA)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, cfg.ListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Id != m.Id {
		t.Fatal("ID not preserved")
	}
	if len(resp.Question) != 1 || resp.Question[0].Name != "www.dept.corp.test." {
		t.Fatal("question not preserved")
	}
	if !resp.RecursionAvailable || resp.Authoritative {
		t.Fatal("want RA=1 AA=0")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("empty answer")
	}

	// Refused: TXT query.
	m2 := new(dns.Msg)
	m2.SetQuestion("www.dept.corp.test.", dns.TypeTXT)
	m2.RecursionDesired = true
	resp2, _, err := c.Exchange(m2, cfg.ListenAddr)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %s", dns.RcodeToString[resp2.Rcode])
	}
}

func TestTCFallbackTCP(t *testing.T) {
	// An authority that always truncates UDP answers; the resolver
	// must retry over TCP to the same server.
	trunc := &truncZone{Zone: NewZone(".", 300, 60)}
	trunc.Delegate("corp.test.", []string{"ns1.corp.test."}, map[string]string{"ns1.corp.test.": "127.0.0.3"})
	addr := fmt.Sprintf("127.0.0.2:%d", testPort+1)
	udp, tcp, err := startAuthServer(addr, trunc)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Shutdown()
	defer tcp.Shutdown()

	if _, _, err := startAuthServer(fmt.Sprintf("127.0.0.3:%d", testPort+1), corpOnly()); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{RootHints: []string{"127.0.0.2"}, UpstreamPort: testPort + 1}
	cfg.setDefaults()
	r := NewResolver(cfg)
	res := mustResolve(t, r, "www.corp.test.", dns.TypeA)
	if got := aRecord(t, res).A.String(); got != "192.0.2.10" {
		t.Fatalf("got %s", got)
	}
}

type truncZone struct{ *Zone }

func (z *truncZone) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		z.Zone.ServeDNS(w, req)
		return
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Truncated = true
	w.WriteMsg(m)
}

func corpOnly() *Zone {
	corp := NewZone("corp.test.", 300, 60)
	corp.AddA("www.corp.test.", "192.0.2.10", 120)
	return corp
}
