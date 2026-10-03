// Command authdemo runs a three-level authoritative hierarchy (root -> test. ->
// example.test.) on loopback addresses 127.0.0.2-127.0.0.4 sharing one port,
// so the recursive resolver can be demonstrated entirely on one machine.
package main

import (
	"flag"
	"log"
	"strconv"

	"github.com/miekg/dns"
)

const ttl = 300

func rr(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		log.Fatalf("bad RR %q: %v", s, err)
	}
	return r
}

func soa(zone, ns string) dns.RR {
	return rr(zone + " " + itoa(ttl) + " IN SOA " + ns + " hostmaster." + zone + " 1 7200 3600 1209600 60")
}

func itoa(i int) string { return strconv.Itoa(i) }

func refer(w dns.ResponseWriter, req *dns.Msg, zone, nsName, glueIP string) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = false
	m.RecursionAvailable = false
	m.Ns = []dns.RR{rr(zone + " 300 IN NS " + nsName)}
	m.Extra = []dns.RR{rr(nsName + " 300 IN A " + glueIP)}
	_ = w.WriteMsg(m)
}

func rootHandler(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 1 && dns.IsSubDomain("test.", req.Question[0].Name) {
		refer(w, req, "test.", "ns.test.", "127.0.0.3")
		return
	}
	nxdomain(w, req, ".", "a.root.")
}

func tldHandler(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 1 && dns.IsSubDomain("example.test.", req.Question[0].Name) {
		refer(w, req, "example.test.", "ns.example.test.", "127.0.0.4")
		return
	}
	nxdomain(w, req, "test.", "ns.test.")
}

func nxdomain(w dns.ResponseWriter, req *dns.Msg, zone, ns string) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeNameError)
	m.Authoritative = true
	m.Ns = []dns.RR{soa(zone, ns)}
	_ = w.WriteMsg(m)
}

func exampleHandler(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	switch {
	case dns.CanonicalName(q.Name) == "www.example.test." && q.Qtype == dns.TypeA:
		m.Answer = []dns.RR{rr("www.example.test. 300 IN A 192.0.2.10")}
	case dns.CanonicalName(q.Name) == "www.example.test." && q.Qtype == dns.TypeAAAA:
		m.Answer = []dns.RR{rr("www.example.test. 300 IN AAAA 2001:db8::10")}
	case dns.CanonicalName(q.Name) == "alias.example.test.":
		m.Answer = []dns.RR{rr("alias.example.test. 120 IN CNAME www.example.test.")}
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, rr("www.example.test. 300 IN A 192.0.2.10"))
		}
	default:
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			// NODATA for known names, NXDOMAIN otherwise.
			if dns.CanonicalName(q.Name) == "www.example.test." || dns.CanonicalName(q.Name) == "alias.example.test." {
				m.Ns = []dns.RR{soa("example.test.", "ns.example.test.")}
			} else {
				m.Rcode = dns.RcodeNameError
				m.Ns = []dns.RR{soa("example.test.", "ns.example.test.")}
			}
		}
	}
	_ = w.WriteMsg(m)
}

func main() {
	port := flag.Int("port", 15354, "port shared by all demo authoritative servers")
	flag.Parse()

	servers := map[string]dns.HandlerFunc{
		"127.0.0.2": rootHandler,
		"127.0.0.3": tldHandler,
		"127.0.0.4": exampleHandler,
	}
	errCh := make(chan error, len(servers)*2)
	for ip, h := range servers {
		for _, network := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: ip + ":" + strconv.Itoa(*port), Net: network, Handler: dns.HandlerFunc(h)}
			go func(s *dns.Server) {
				log.Printf("auth on %s (%s)", s.Addr, s.Net)
				errCh <- s.ListenAndServe()
			}(srv)
		}
	}
	log.Fatal(<-errCh)
}
