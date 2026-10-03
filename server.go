package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// server validates inbound queries and hands them to the resolver.
type server struct {
	res *Resolver
}

func (s *server) handle(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	resp.RecursionAvailable = true
	resp.Authoritative = false

	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}
	q := req.Question[0]
	if !req.RecursionDesired || q.Qclass != dns.ClassINET ||
		(q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
		resp.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(resp)
		return
	}

	res, err := s.res.Resolve(q.Name, q.Qtype)
	if err != nil {
		log.Printf("resolve %s %s: %v", q.Name, dns.TypeToString[q.Qtype], err)
		resp.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(resp)
		return
	}
	resp.Rcode = res.rcode
	resp.Answer = res.answer
	if res.soa != nil {
		resp.Ns = []dns.RR{res.soa}
	}
	_ = w.WriteMsg(resp)
}

func serve(cfg *Config, res *Resolver) error {
	h := &server{res: res}
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.ListenPort)
	errCh := make(chan error, 2)
	for _, net := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: addr, Net: net, Handler: dns.HandlerFunc(h.handle)}
		go func(s *dns.Server) {
			log.Printf("listening on %s (%s)", s.Addr, s.Net)
			errCh <- s.ListenAndServe()
		}(srv)
	}
	return <-errCh
}
