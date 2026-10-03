package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// upstreamClient sends RD=0 queries to authoritative servers and validates the
// responses. It never consults the system resolver or any recursive forwarder.
type upstreamClient struct {
	port    int
	timeout time.Duration
	udp     *dns.Client
	tcp     *dns.Client
}

func newUpstreamClient(port int, timeout time.Duration) *upstreamClient {
	return &upstreamClient{
		port:    port,
		timeout: timeout,
		udp:     &dns.Client{Net: "udp", Timeout: timeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}
}

// exchange queries server (IPv4 string) for qname/qtype with RD=0. It verifies
// the transaction ID and echoed question, and retries over TCP against the same
// server when a UDP response arrives truncated.
func (u *upstreamClient) exchange(serverIPv4, qname string, qtype uint16) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	req.RecursionDesired = false
	addr := fmt.Sprintf("%s:%d", serverIPv4, u.port)

	resp, _, err := u.udp.Exchange(req, addr)
	if err != nil {
		return nil, err
	}
	if err := validateResponse(req, resp); err != nil {
		return nil, err
	}
	if resp.Truncated {
		resp, _, err = u.tcp.Exchange(req, addr)
		if err != nil {
			return nil, fmt.Errorf("tcp retry after TC: %w", err)
		}
		if err := validateResponse(req, resp); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// validateResponse checks transaction ID and question echo. The miekg client
// already matches the source address/port of UDP replies; ID and question are
// verified here explicitly.
func validateResponse(req, resp *dns.Msg) error {
	if resp.Id != req.Id {
		return fmt.Errorf("mismatched transaction ID")
	}
	if !resp.Response {
		return fmt.Errorf("message is not a response")
	}
	if len(resp.Question) != 1 {
		return fmt.Errorf("response does not echo exactly one question")
	}
	q, rq := req.Question[0], resp.Question[0]
	if !equalNames(q.Name, rq.Name) || q.Qtype != rq.Qtype || q.Qclass != rq.Qclass {
		return fmt.Errorf("response question mismatch")
	}
	return nil
}

func equalNames(a, b string) bool {
	return dns.CanonicalName(a) == dns.CanonicalName(b)
}
