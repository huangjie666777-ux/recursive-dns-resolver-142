package main

import (
	"github.com/miekg/dns"
	"net"
)

// Server is the client-facing UDP/TCP DNS server. It accepts only
// single-question, IN-class, RD=1 A/AAAA queries.
type Server struct {
	resolver *Resolver
	addr     string
	udp      *dns.Server
	tcp      *dns.Server
}

func NewServer(cfg *Config, resolver *Resolver) *Server {
	s := &Server{resolver: resolver, addr: cfg.ListenAddr}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.udp = &dns.Server{Addr: s.addr, Net: "udp", Handler: mux}
	s.tcp = &dns.Server{Addr: s.addr, Net: "tcp", Handler: mux}
	return s
}

// ListenAndServe serves UDP and TCP on the configured address.
func (s *Server) ListenAndServe() error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()
	return <-errCh
}

// ActivateAndServe starts both listeners in the background (tests, demo).
func (s *Server) ActivateAndServe() error {
	pc, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		pc.Close()
		return err
	}
	s.udp.PacketConn = pc
	s.tcp.Listener = l
	go s.udp.ActivateAndServe()
	go s.tcp.ActivateAndServe()
	return nil
}

// Shutdown stops both listeners.
func (s *Server) Shutdown() {
	s.udp.Shutdown()
	s.tcp.Shutdown()
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req) // preserves ID, question and RD
	m.RecursionAvailable = true
	m.Authoritative = false

	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET || !req.RecursionDesired ||
		(q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA) {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	res, err := s.resolver.Resolve(q.Name, q.Qtype)
	if err != nil {
		// Timeouts, exhausted budgets/deadlines and broken upstreams
		// are SERVFAIL, never NXDOMAIN.
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	m.Rcode = res.rcode
	m.Answer = res.answers
	if res.soa != nil {
		m.Ns = append(m.Ns, res.soa)
	}
	w.WriteMsg(m)
}
