package main

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testPort = 18354

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("bad RR %q: %v", s, err)
	}
	return r
}

func startAuth(t *testing.T, ip string, h dns.HandlerFunc) {
	t.Helper()
	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: ip + ":" + itoaTest(testPort), Net: network, Handler: h}
		go func() { _ = srv.ListenAndServe() }()
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
}

func itoaTest(i int) string { return strconv.Itoa(i) }

func testConfig() *Config {
	return &Config{
		ListenAddr:        "127.0.0.1",
		ListenPort:        18353,
		RootHints:         []RootHint{{Name: "a.root.", IPv4: "127.0.0.2"}},
		UpstreamPort:      testPort,
		UpstreamTimeoutMs: 800,
		QueryDeadlineSec:  10,
		MaxUpstream:       64,
		MaxDepth:          16,
		CacheMaxEntries:   16,
		CacheMaxNegTTL:    3600,
	}
}

// testHierarchy installs root -> test. -> example.test. on 127.0.0.2/3/4.
func testHierarchy(t *testing.T) {
	t.Helper()
	startAuth(t, "127.0.0.2", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Ns = []dns.RR{mustRR(t, "test. 300 IN NS ns.test.")}
		m.Extra = []dns.RR{
			mustRR(t, "ns.test. 300 IN A 127.0.0.3"),
			// Untrusted: not one of the delegated NS names.
			mustRR(t, "evil.test. 300 IN A 9.9.9.9"),
		}
		_ = w.WriteMsg(m)
	})
	startAuth(t, "127.0.0.3", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Ns = []dns.RR{mustRR(t, "example.test. 300 IN NS ns.example.test.")}
		m.Extra = []dns.RR{mustRR(t, "ns.example.test. 300 IN A 127.0.0.4")}
		_ = w.WriteMsg(m)
	})
	startAuth(t, "127.0.0.4", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		q := req.Question[0]
		switch dns.CanonicalName(q.Name) {
		case "www.example.test.":
			if q.Qtype == dns.TypeA {
				m.Answer = []dns.RR{mustRR(t, "www.example.test. 300 IN A 192.0.2.10")}
			} else {
				m.Ns = []dns.RR{mustRR(t, "example.test. 300 IN SOA ns.example.test. h.example.test. 1 7200 3600 1209600 60")}
			}
		case "alias.example.test.":
			m.Answer = []dns.RR{mustRR(t, "alias.example.test. 120 IN CNAME www.example.test.")}
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, mustRR(t, "www.example.test. 300 IN A 192.0.2.10"))
			}
		default:
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{mustRR(t, "example.test. 300 IN SOA ns.example.test. h.example.test. 1 7200 3600 1209600 60")}
		}
		_ = w.WriteMsg(m)
	})
	time.Sleep(100 * time.Millisecond)
}

func TestResolveA(t *testing.T) {
	testHierarchy(t)
	r := newResolver(testConfig())
	res, err := r.Resolve("www.example.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if res.rcode != dns.RcodeSuccess || len(res.answer) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	a, ok := res.answer[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.10" {
		t.Fatalf("unexpected answer: %v", res.answer)
	}
}

func TestCNAMEChain(t *testing.T) {
	testHierarchy(t)
	r := newResolver(testConfig())
	res, err := r.Resolve("alias.example.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(res.answer) != 2 {
		t.Fatalf("want full chain of 2 RRs, got %v", res.answer)
	}
	if _, ok := res.answer[0].(*dns.CNAME); !ok {
		t.Fatalf("first record must be CNAME: %v", res.answer[0])
	}
	if _, ok := res.answer[1].(*dns.A); !ok {
		t.Fatalf("chain must end at A: %v", res.answer[1])
	}
}

func TestNXDOMAINvsNODATA(t *testing.T) {
	testHierarchy(t)
	r := newResolver(testConfig())
	nx, err := r.Resolve("missing.example.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if nx.rcode != dns.RcodeNameError || nx.soa == nil {
		t.Fatalf("want NXDOMAIN with SOA, got %+v", nx)
	}
	nd, err := r.Resolve("www.example.test.", dns.TypeAAAA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if nd.rcode != dns.RcodeSuccess || len(nd.answer) != 0 || nd.soa == nil {
		t.Fatalf("want NODATA with SOA, got %+v", nd)
	}
}

func TestCacheHitDecrementsTTL(t *testing.T) {
	testHierarchy(t)
	r := newResolver(testConfig())
	first, err := r.Resolve("www.example.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := r.Resolve("WWW.EXAMPLE.TEST.", dns.TypeA) // case-insensitive hit
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ttl1 := first.answer[0].Header().Ttl
	ttl2 := second.answer[0].Header().Ttl
	if ttl2 >= ttl1 {
		t.Fatalf("cached TTL must decrease: %d -> %d", ttl1, ttl2)
	}
}

func TestNegativeCached(t *testing.T) {
	testHierarchy(t)
	r := newResolver(testConfig())
	if _, err := r.Resolve("missing.example.test.", dns.TypeA); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	rcode, _, soa, ok := r.cache.get("missing.example.test.", dns.TypeA)
	if !ok || rcode != dns.RcodeNameError || soa == nil {
		t.Fatalf("negative answer with SOA must be cached")
	}
}

func TestCNAMELoop(t *testing.T) {
	startAuth(t, "127.0.0.2", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		m.Answer = []dns.RR{mustRR(t, "loop.test. 300 IN CNAME loop.test.")}
		_ = w.WriteMsg(m)
	})
	time.Sleep(100 * time.Millisecond)
	r := newResolver(testConfig())
	if _, err := r.Resolve("loop.test.", dns.TypeA); err == nil {
		t.Fatal("CNAME loop must fail (SERVFAIL)")
	}
}

func TestAllNSDownSERVFAIL(t *testing.T) {
	// No authoritative servers running at all.
	r := newResolver(testConfig())
	if _, err := r.Resolve("www.example.test.", dns.TypeA); err == nil {
		t.Fatal("unreachable nameservers must fail (SERVFAIL), never NXDOMAIN")
	}
}

func TestBudgetExhausted(t *testing.T) {
	testHierarchy(t)
	cfg := testConfig()
	cfg.MaxUpstream = 1
	r := newResolver(cfg)
	if _, err := r.Resolve("www.example.test.", dns.TypeA); err == nil {
		t.Fatal("budget exhaustion must fail (SERVFAIL)")
	}
}

func TestConcurrentSameQuery(t *testing.T) {
	testHierarchy(t)
	r := newResolver(testConfig())
	var wg sync.WaitGroup
	results := make([]*resolveResult, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := r.Resolve("www.example.test.", dns.TypeA)
			if err != nil {
				t.Errorf("resolve: %v", err)
				return
			}
			results[i] = res
		}(i)
	}
	wg.Wait()
	// Mutating one copy must not affect others.
	results[0].answer[0].Header().Ttl = 1
	for i := 1; i < len(results); i++ {
		if results[i] == nil || results[i].answer[0].Header().Ttl == 1 {
			t.Fatalf("response %d shares mutable state", i)
		}
	}
}

func TestTCRetryOverTCP(t *testing.T) {
	startAuth(t, "127.0.0.2", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		if _, isTCP := w.RemoteAddr().(*net.TCPAddr); !isTCP {
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = []dns.RR{mustRR(t, "big.test. 300 IN A 192.0.2.99")}
		_ = w.WriteMsg(m)
	})
	time.Sleep(100 * time.Millisecond)
	r := newResolver(testConfig())
	res, err := r.Resolve("big.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("TC must trigger TCP retry: %v", err)
	}
	if a, ok := res.answer[0].(*dns.A); !ok || a.A.String() != "192.0.2.99" {
		t.Fatalf("unexpected answer: %v", res.answer)
	}
}
