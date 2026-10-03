package main

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Zone is a minimal in-memory authoritative server used by the local
// multi-level demo and the tests.
type Zone struct {
	Origin      string
	Records     map[string][]dns.RR // key: lower-cased FQDN owner
	Delegations map[string][]string // child zone FQDN -> NS names
	Glue        map[string]string   // NS name -> IPv4 (only sent when in-bailiwick)
	SOA         *dns.SOA
}

func NewZone(origin string, soaTTL, minimum uint32) *Zone {
	origin = strings.ToLower(dns.Fqdn(origin))
	z := &Zone{
		Origin:      origin,
		Records:     make(map[string][]dns.RR),
		Delegations: make(map[string][]string),
		Glue:        make(map[string]string),
	}
	z.SOA = &dns.SOA{
		Hdr:     dns.RR_Header{Name: origin, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:      "ns1." + origin,
		Mbox:    "hostmaster." + origin,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  minimum,
	}
	return z
}

func hdr(name string, rtype uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: rtype, Class: dns.ClassINET, Ttl: ttl}
}

// AddA adds an A record.
func (z *Zone) AddA(name, ip string, ttl uint32) {
	a := &dns.A{Hdr: hdr(name, dns.TypeA, ttl)}
	a.A = net.ParseIP(ip).To4()
	z.add(a)
}

// AddAAAA adds an AAAA record.
func (z *Zone) AddAAAA(name, ip string, ttl uint32) {
	aaaa := &dns.AAAA{Hdr: hdr(name, dns.TypeAAAA, ttl)}
	aaaa.AAAA = net.ParseIP(ip)
	z.add(aaaa)
}

// AddCNAME adds a CNAME record.
func (z *Zone) AddCNAME(name, target string, ttl uint32) {
	z.add(&dns.CNAME{Hdr: hdr(name, dns.TypeCNAME, ttl), Target: dns.Fqdn(target)})
}

// AddTXT adds a TXT record (used to create NODATA names for A/AAAA).
func (z *Zone) AddTXT(name, txt string, ttl uint32) {
	z.add(&dns.TXT{Hdr: hdr(name, dns.TypeTXT, ttl), Txt: []string{txt}})
}

// Delegate registers a child-zone delegation with optional glue.
func (z *Zone) Delegate(child string, nsNames []string, glue map[string]string) {
	child = strings.ToLower(dns.Fqdn(child))
	for i, ns := range nsNames {
		nsNames[i] = dns.Fqdn(ns)
	}
	z.Delegations[child] = nsNames
	for ns, ip := range glue {
		z.Glue[strings.ToLower(dns.Fqdn(ns))] = ip
	}
}

func (z *Zone) add(rr dns.RR) {
	key := strings.ToLower(dns.Fqdn(rr.Header().Name))
	z.Records[key] = append(z.Records[key], rr)
}

// ServeDNS implements dns.Handler as an authoritative-only server.
func (z *Zone) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = false
	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(dns.Fqdn(q.Name))

	// Deepest delegation that is an ancestor of the question name.
	best := ""
	for dz := range z.Delegations {
		if dns.IsSubDomain(dz, name) && (best == "" || dns.CountLabel(dz) > dns.CountLabel(best)) {
			best = dz
		}
	}
	if best != "" {
		for _, ns := range z.Delegations[best] {
			m.Ns = append(m.Ns, &dns.NS{Hdr: hdr(best, dns.TypeNS, 300), Ns: ns})
			if ip, ok := z.Glue[strings.ToLower(ns)]; ok && dns.IsSubDomain(best, ns) {
				a := &dns.A{Hdr: hdr(ns, dns.TypeA, 300)}
				a.A = net.ParseIP(ip).To4()
				m.Extra = append(m.Extra, a)
			}
		}
		w.WriteMsg(m)
		return
	}

	if !dns.IsSubDomain(z.Origin, name) {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	rrs := z.Records[name]
	if strings.EqualFold(name, z.Origin) && q.Qtype == dns.TypeSOA {
		m.Answer = append(m.Answer, dns.Copy(z.SOA))
		w.WriteMsg(m)
		return
	}
	matched := false
	for _, rr := range rrs {
		t := rr.Header().Rrtype
		if t == q.Qtype || t == dns.TypeCNAME {
			m.Answer = append(m.Answer, dns.Copy(rr))
			matched = true
		}
	}
	if matched {
		w.WriteMsg(m)
		return
	}
	// Negative answers carry the zone SOA in the authority section.
	m.Ns = append(m.Ns, dns.Copy(z.SOA))
	if len(rrs) == 0 {
		m.Rcode = dns.RcodeNameError // NXDOMAIN
	} // else NOERROR with empty answer: NODATA
	w.WriteMsg(m)
}

// startAuthServer runs an authoritative zone on UDP+TCP at addr.
func startAuthServer(addr string, z dns.Handler) (*dns.Server, *dns.Server, error) {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: z}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: z}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	udp.PacketConn = pc
	tcp.Listener = l
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	return udp, tcp, nil
}
