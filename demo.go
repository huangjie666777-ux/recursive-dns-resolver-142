package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// Demo topology (all on 127.0.0.0/8, one shared upstream port):
//
//	127.0.0.2  root "."           delegates corp.test. (glue -> 127.0.0.3)
//	127.0.0.3  corp.test.         delegates dept.corp.test. (glue -> 127.0.0.4)
//	                              delegates eng.corp.test.  (NO glue; NS is ns1.corp.test)
//	127.0.0.4  dept.corp.test.    www A, alias CNAME, loop1/loop2 CNAMEs, txt-only TXT
//	127.0.0.5  eng.corp.test.     www A
func buildDemoZones(port int) map[string]*Zone {
	addr := func(octet int) string { return fmt.Sprintf("127.0.0.%d", octet) }

	root := NewZone(".", 300, 60)
	root.Delegate("corp.test.", []string{"ns1.corp.test."}, map[string]string{
		"ns1.corp.test.": addr(3),
	})

	corp := NewZone("corp.test.", 300, 60)
	corp.AddA("www.corp.test.", "192.0.2.10", 120)
	corp.AddAAAA("www.corp.test.", "2001:db8::10", 120)
	corp.Delegate("dept.corp.test.", []string{"ns1.dept.corp.test."}, map[string]string{
		"ns1.dept.corp.test.": addr(4),
	})
	corp.Delegate("eng.corp.test.", []string{"ns1.corp.test."}, nil)
	corp.AddA("ns1.corp.test.", addr(5), 300)

	dept := NewZone("dept.corp.test.", 300, 60)
	dept.AddA("www.dept.corp.test.", "192.0.2.20", 120)
	dept.AddCNAME("alias.dept.corp.test.", "www.dept.corp.test.", 90)
	dept.AddCNAME("loop1.dept.corp.test.", "loop2.dept.corp.test.", 60)
	dept.AddCNAME("loop2.dept.corp.test.", "loop1.dept.corp.test.", 60)
	dept.AddTXT("txt-only.dept.corp.test.", "no address here", 60)

	eng := NewZone("eng.corp.test.", 300, 60)
	eng.AddA("www.eng.corp.test.", "192.0.2.30", 120)

	return map[string]*Zone{
		addr(2): root,
		addr(3): corp,
		addr(4): dept,
		addr(5): eng,
	}
}

func startDemoAuthorities(port int) ([]*dns.Server, error) {
	var servers []*dns.Server
	for ip, zone := range buildDemoZones(port) {
		addr := fmt.Sprintf("%s:%d", ip, port)
		udp, tcp, err := startAuthServer(addr, zone)
		if err != nil {
			return nil, fmt.Errorf("start authority %s: %w", addr, err)
		}
		servers = append(servers, udp, tcp)
		log.Printf("authority for %s on %s", zone.Origin, addr)
	}
	return servers, nil
}

func demoConfig() *Config {
	cfg := &Config{
		ListenAddr:      "127.0.0.1:8053",
		RootHints:       []string{"127.0.0.2"},
		UpstreamPort:    15353,
		CacheMaxEntries: 256,
	}
	cfg.setDefaults()
	return cfg
}

func runDemo() {
	if _, err := startDemoAuthorities(15353); err != nil {
		log.Fatal(err)
	}
	cfg := demoConfig()
	resolver := NewResolver(cfg)
	srv := NewServer(cfg, resolver)
	if err := srv.ActivateAndServe(); err != nil {
		log.Fatal(err)
	}
	log.Printf("resolver listening on %s", cfg.ListenAddr)
	time.Sleep(200 * time.Millisecond)

	queries := []struct {
		name  string
		qtype uint16
	}{
		{"www.corp.test.", dns.TypeA},
		{"www.dept.corp.test.", dns.TypeA},
		{"alias.dept.corp.test.", dns.TypeA},
		{"www.eng.corp.test.", dns.TypeA},
		{"nosuch.dept.corp.test.", dns.TypeA},
		{"txt-only.dept.corp.test.", dns.TypeA},
		{"loop1.dept.corp.test.", dns.TypeA},
	}
	c := &dns.Client{Timeout: 5 * time.Second}
	for _, q := range queries {
		m := new(dns.Msg)
		m.SetQuestion(q.name, q.qtype)
		m.RecursionDesired = true
		resp, _, err := c.Exchange(m, cfg.ListenAddr)
		if err != nil {
			fmt.Printf("%-28s error: %v\n", q.name, err)
			continue
		}
		fmt.Printf("%-28s -> %s\n", q.name, dns.RcodeToString[resp.Rcode])
		for _, rr := range resp.Answer {
			fmt.Printf("    %s\n", rr.String())
		}
		for _, rr := range resp.Ns {
			fmt.Printf("    auth: %s\n", rr.String())
		}
	}
	fmt.Println("demo authorities and resolver still running; Ctrl-C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.Shutdown()
}
